mod output;

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use lvau_core::bundle::{
    extract_bundle, inspect_bundle, list_bundle, pack_directory, verify_bundle, PaddingProfile,
};
use lvau_core::crypto::{
    decrypt_file_keypair, decrypt_file_keypair_with_overwrite, decrypt_file_password,
    decrypt_file_password_with_overwrite, encrypt_file_keypairs,
    encrypt_file_keypairs_with_overwrite, encrypt_file_password,
    encrypt_file_password_with_overwrite,
    keys::{generate_keypair, HybridPrivateKey, HybridPublicKey},
    verify_file_keypair, verify_file_password,
};
use lvau_core::recovery::{combine_shares, split_secret, RecoveryShare};
use lvau_core::signing::{
    generate_signing_keypair, key_fingerprint, load_signing_key, load_verify_key, save_signing_key,
    save_verify_key, sign_file, verify_signature,
};
use lvau_protocol::envelope::{KdfParams, Recipient, SecurityProfile};
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "lvau-cli")]
#[command(version)]
#[command(about = "Boring, inspectable file encryption.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging without printing secrets.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new hybrid keypair (X25519 + ML-KEM-768, experimental).
    Keygen {
        /// Base path to save the key files (.lvau-key and .lvau-pub will be appended).
        #[arg(short, long)]
        out_base: PathBuf,

        /// Replace existing key files.
        #[arg(short, long)]
        force: bool,
    },
    /// Encrypt a file.
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output file path.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Use password encryption.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use public key encryption.
        #[arg(long)]
        pub_key: Option<PathBuf>,

        /// Use a RecipientGroup TOML file for multi-recipient encryption.
        #[arg(long)]
        recipient_group: Option<PathBuf>,

        /// Security profile (for v2 payloads and password KDF; default balanced).
        #[arg(long)]
        profile: Option<String>,

        /// Output format (v2 by default; v3 is experimental).
        #[arg(long, default_value = "v2")]
        format: String,

        /// Experimental v3 payload suite (lv3-xc20p or lv3-aesgcmsiv-xc20p).
        #[arg(long)]
        suite: Option<String>,

        /// Experimental v3 recipient suite (ml-kem-768, x25519-hpke, or hybrid-x25519-mlkem).
        #[arg(long)]
        recipient_suite: Option<String>,

        /// Use an additional cryptographic seed (pepper).
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Read the seed from a local file instead of prompting.
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Create an experimental Windows self-extracting archive.
        #[arg(long, default_value_t = false)]
        sfx: bool,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,

        /// Check against a local CapsulePolicy TOML file before encrypting.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Allow overriding policy violations (logs an override flag in metadata).
        #[arg(long, default_value_t = false)]
        allow_policy_override: bool,
    },
    /// Decrypt a file.
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output file path.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Use password decryption.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use private key decryption.
        #[arg(long)]
        priv_key: Option<PathBuf>,

        /// Use an additional cryptographic seed (pepper).
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Read the seed from a local file instead of prompting.
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Inspect public envelope metadata without decrypting the payload.
    Inspect {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output in JSON format for automation.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify file integrity without writing plaintext to disk.
    Verify {
        /// Input file path.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Use password verification.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use private key verification.
        #[arg(long)]
        priv_key: Option<PathBuf>,

        /// Use an additional cryptographic seed (pepper).
        #[arg(long, default_value_t = false)]
        seed: bool,

        /// Read the seed from a local file instead of prompting.
        #[arg(long)]
        seed_file: Option<PathBuf>,

        /// Output in JSON format for automation.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Run preflight verification on an encrypted capsule (does not decrypt data).
    Preflight {
        /// Input .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Verify key (.lvau-verify) to check author signature.
        #[arg(long)]
        verify_key: Option<PathBuf>,

        /// Policy file to lint the capsule against.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Generate a comprehensive verification report for a capsule.
    Report {
        /// Input .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Verify key (.lvau-verify) to check author signature.
        #[arg(long)]
        verify_key: Option<PathBuf>,

        /// Policy file to lint the capsule against.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Use password verification.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use private key verification.
        #[arg(long)]
        priv_key: Option<PathBuf>,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Manage and lint capsule policies.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Pack, extract, inspect, or verify encrypted directory bundles.
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Generate an Ed25519 signing keypair.
    SignKeygen {
        /// Base path to save the key files (.lvau-sign and .lvau-verify will be appended).
        #[arg(short, long)]
        out_base: PathBuf,

        /// Replace existing key files.
        #[arg(short, long)]
        force: bool,
    },
    /// Manage release artifacts.
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    /// Manage recipients and recipient groups.
    Recipients {
        #[command(subcommand)]
        action: RecipientsAction,
    },
    /// Re-encrypt an experimental v3 capsule to rotate its root key.
    Rekey {
        #[command(subcommand)]
        action: RekeyAction,
    },
    /// Manage recovery metadata.
    Recovery {
        #[command(subcommand)]
        action: RecoveryAction,
    },
    /// Manage small structured secrets (API keys, .env files).
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Sign an encrypted .lvau file with an Ed25519 signing key.
    Sign {
        /// Input .lvau file to sign.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Path to the signing key (.lvau-sign).
        #[arg(long)]
        signing_key: PathBuf,

        /// Output signed .lvau file.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Optional comment to include in the signature.
        #[arg(long)]
        comment: Option<String>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Verify an Ed25519 signature on an .lvau file.
    VerifySignature {
        /// Input .lvau file to verify.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Path to the verifying key (.lvau-verify).
        #[arg(long)]
        verify_key: PathBuf,
    },
    /// Add an approval seal to an encrypted .lvau capsule.
    Approve {
        /// Input .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output approved .lvau file.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Path to the signing key (.lvau-sign).
        #[arg(long)]
        signing_key: PathBuf,

        /// Optional comment for this approval.
        #[arg(long)]
        comment: Option<String>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Verify approval seals on an .lvau capsule.
    Approvals {
        /// Input .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Verify key (.lvau-verify) to check for.
        #[arg(long)]
        verify_key: PathBuf,
    },
    /// Run built-in integration tests to ensure cryptography is functioning correctly.
    SelfTest,
    /// Print environment diagnostics and check for required dependencies.
    Doctor,
}

#[derive(Subcommand)]
enum ReleaseAction {
    /// Attach release metadata to a capsule.
    Attach {
        /// Input .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output .lvau file.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Project name (e.g. lvau-core)
        #[arg(long)]
        project_name: Option<String>,

        /// Version string (e.g. v0.4.0)
        #[arg(long)]
        version: Option<String>,

        /// Git commit hash
        #[arg(long)]
        git_commit: Option<String>,

        /// Build timestamp (ISO 8601)
        #[arg(long)]
        build_timestamp: Option<String>,

        /// Replace existing output file.
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryAction {
    /// Attach recovery metadata to a capsule.
    Attach {
        /// Input .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// Output .lvau file.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Metadata to attach as bytes.
        #[arg(long)]
        data: String,

        /// Replace existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Split a file (e.g. a key) into Shamir Secret Sharing recovery shares.
    Split {
        /// Input file to split
        #[arg(short, long)]
        in_file: PathBuf,

        /// Number of shares to generate
        #[arg(short, long)]
        shares: u8,

        /// Threshold of shares required to combine
        #[arg(short, long)]
        threshold: u8,

        /// Output directory for the shares
        #[arg(short, long)]
        out_dir: PathBuf,
    },
    /// Combine Shamir shares to recover the data.
    Combine {
        /// Directory containing the share files
        #[arg(long)]
        shares_dir: PathBuf,

        /// Output file for the recovered data
        #[arg(short, long)]
        out_file: PathBuf,

        /// Replace existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Inspect a recovery share file.
    Inspect {
        /// Input .lvau-share file
        #[arg(short, long)]
        in_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Encrypt a secret file. Outputs <in_file>.lvau
    Encrypt {
        /// Input file
        #[arg(short, long)]
        in_file: PathBuf,
    },
    /// Decrypt a secret file. Outputs <in_file> without .lvau
    Decrypt {
        /// Input .lvau file
        #[arg(short, long)]
        in_file: PathBuf,
    },
    /// Edit an encrypted secret file in your default editor
    Edit {
        /// Input .lvau file
        #[arg(short, long)]
        in_file: PathBuf,
    },
    /// Print the decrypted contents of a secret file to stdout
    Print {
        /// Input .lvau file
        #[arg(short, long)]
        in_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum RekeyAction {
    /// Add a recipient to a v3 file without rewriting its payload.
    AddRecipient {
        #[arg(short, long)]
        in_file: PathBuf,
        #[arg(short, long)]
        out_file: PathBuf,
        #[arg(long, default_value_t = false)]
        password: bool,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long)]
        priv_key: Option<PathBuf>,
        #[arg(long)]
        pub_key: PathBuf,
        #[arg(long, default_value = "ml-kem-768")]
        recipient_suite: String,
        #[arg(short, long)]
        force: bool,
    },
    /// Remove a recipient from a mutable v3 file.
    RemoveRecipient {
        #[arg(short, long)]
        in_file: PathBuf,
        #[arg(short, long)]
        out_file: PathBuf,
        #[arg(long, default_value_t = false)]
        password: bool,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long)]
        priv_key: Option<PathBuf>,
        #[arg(long)]
        pub_key: PathBuf,
        #[arg(long, default_value = "ml-kem-768")]
        recipient_suite: String,
        #[arg(short, long)]
        force: bool,
    },
    /// Change the password wrapping a mutable v3 file's root key.
    ChangePassword {
        #[arg(short, long)]
        in_file: PathBuf,
        #[arg(short, long)]
        out_file: PathBuf,
        #[arg(long, default_value_t = false)]
        password: bool,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long)]
        priv_key: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        new_password: bool,
        #[arg(long)]
        new_password_file: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(short, long)]
        force: bool,
    },
    /// Convert A3 to A4, preserving every original X25519 recipient and payload frame.
    ConvertA3 {
        #[arg(short, long)]
        in_file: PathBuf,
        #[arg(short, long)]
        out_file: PathBuf,
        /// A3 source recipient private key (its public key is retained automatically).
        #[arg(long)]
        priv_key: PathBuf,
        /// Public keys for the other A3 recipients; the group must cover all original slots.
        #[arg(long)]
        recipient_group: Option<PathBuf>,
        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
    /// Rotate the root key of a password-protected legacy v3 file by fully re-encrypting it.
    RotateRoot {
        /// Input legacy password-protected v3 .lvau file.
        #[arg(short, long)]
        in_file: PathBuf,

        /// New output .lvau file.
        #[arg(short, long)]
        out_file: PathBuf,

        /// Prompt for the current password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the current password from a local file.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Prompt for and confirm the new password.
        #[arg(long, default_value_t = false)]
        new_password: bool,

        /// Read the new password from a local file.
        #[arg(long)]
        new_password_file: Option<PathBuf>,

        /// Argon2id profile for the new capsule.
        #[arg(long, default_value = "balanced")]
        profile: String,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum BundleAction {
    /// Pack a directory into a single encrypted .lvau bundle.
    Pack {
        /// Input directory to pack.
        #[arg(long)]
        in_dir: PathBuf,

        /// Output .lvau file.
        #[arg(long)]
        out_file: PathBuf,

        /// Use password encryption.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Use a RecipientGroup TOML file for multi-recipient encryption.
        #[arg(long)]
        recipient_group: Option<PathBuf>,

        /// Security profile.
        #[arg(long, default_value = "balanced")]
        profile: String,

        /// Follow symlink targets and pack their bytes as regular files (rejected by default).
        #[arg(long, default_value_t = false)]
        allow_symlinks: bool,

        /// Metadata privacy profile (minimal, balanced, verbose).
        #[arg(long, default_value = "minimal")]
        metadata_profile: String,

        /// Size padding profile (none, bucket, fixed:<SIZE>).
        #[arg(long, default_value = "none")]
        pad: String,

        /// Optional public label visible in inspect output.
        #[arg(long)]
        public_label: Option<String>,

        /// Replace an existing output file.
        #[arg(short, long)]
        force: bool,

        /// Check against a local CapsulePolicy TOML file before encrypting.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Allow overriding policy violations (logs an override flag in metadata).
        #[arg(long, default_value_t = false)]
        allow_policy_override: bool,
    },
    /// Inspect public envelope metadata of a bundle.
    Inspect {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Diff two encrypted bundles.
    Diff {
        /// Old .lvau bundle file.
        #[arg(long)]
        old_file: PathBuf,

        /// New .lvau bundle file.
        #[arg(long)]
        new_file: PathBuf,

        /// Use password for old file.
        #[arg(long, default_value_t = false)]
        old_password: bool,

        /// Read the password for old file from a local file.
        #[arg(long)]
        old_password_file: Option<PathBuf>,

        /// Use password for new file.
        #[arg(long, default_value_t = false)]
        new_password: bool,

        /// Read the password for new file from a local file.
        #[arg(long)]
        new_password_file: Option<PathBuf>,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// List files in a bundle (requires password).
    List {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Use password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Extract files from a bundle.
    Extract {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Output directory.
        #[arg(long)]
        out_dir: PathBuf,

        /// Use password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Legacy compatibility flag; manifests contain regular files and symlink targets are always rejected.
        #[arg(long, default_value_t = false)]
        allow_symlinks: bool,

        /// Preview extraction without writing files.
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Replace existing files.
        #[arg(short, long)]
        force: bool,
    },
    /// Verify bundle integrity without extracting.
    Verify {
        /// Input .lvau bundle file.
        #[arg(long)]
        in_file: PathBuf,

        /// Use password.
        #[arg(long, default_value_t = false)]
        password: bool,

        /// Read the password from a local file instead of prompting.
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Inspect a policy file.
    Inspect {
        #[arg(long)]
        in_file: PathBuf,
    },
    /// Lint an existing .lvau file against a policy.
    Lint {
        #[arg(long)]
        in_file: PathBuf,

        #[arg(long)]
        policy: PathBuf,

        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Create a new default policy file.
    Create {
        #[arg(long)]
        out_file: PathBuf,

        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum RecipientsAction {
    /// Manage recipient groups
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
}

#[derive(Subcommand)]
enum GroupAction {
    /// Create a new recipient group
    Create {
        /// File path for the new group (e.g., group.toml)
        name: String,
    },
    /// Add a recipient to a group
    Add {
        /// File path of the group (e.g., group.toml)
        name: String,
        /// Public key file path (.lvau-pub)
        #[arg(long)]
        pub_key: PathBuf,
    },
    /// Remove a recipient from a group
    Remove {
        /// File path of the group (e.g., group.toml)
        name: String,
        /// Name of the recipient or key fingerprint to remove
        #[arg(long)]
        fingerprint: String,
    },
    /// List recipients in a group
    List {
        /// File path of the group (e.g., group.toml)
        name: String,
    },
}

#[derive(Debug)]
enum CliError {
    Message(String),
    Io(std::io::Error),
    Crypto(lvau_core::crypto::CryptoError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Message(message) => write!(f, "{message}"),
            CliError::Io(error) => write!(f, "{error}"),
            CliError::Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Message(format!("JSON serialization failed: {error}"))
    }
}

impl From<lvau_core::crypto::CryptoError> for CliError {
    fn from(error: lvau_core::crypto::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<lvau_core::bundle::BundleError> for CliError {
    fn from(error: lvau_core::bundle::BundleError) -> Self {
        Self::Message(error.to_string())
    }
}

impl From<lvau_core::signing::SigningError> for CliError {
    fn from(error: lvau_core::signing::SigningError) -> Self {
        Self::Message(error.to_string())
    }
}

const MAX_SECRET_FILE_SIZE: u64 = 64 * 1024;

fn prompt_password(prompt: &str) -> Result<String, CliError> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    read_password().map_err(CliError::Io)
}

fn read_secret_file(path: &Path) -> Result<String, CliError> {
    // Keep metadata checks and reads tied to the same open file handle so a
    // path swap cannot change the file after validation.
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CliError::Message(format!(
            "Secret file is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_SECRET_FILE_SIZE {
        return Err(CliError::Message(format!(
            "Secret file is too large: {} (maximum {} bytes)",
            path.display(),
            MAX_SECRET_FILE_SIZE
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::Message(format!(
                "Secret file permissions are too broad: {} (use chmod 600)",
                path.display()
            )));
        }
    }

    let mut value = String::new();
    file.take(MAX_SECRET_FILE_SIZE + 1)
        .read_to_string(&mut value)?;
    if value.len() as u64 > MAX_SECRET_FILE_SIZE {
        return Err(CliError::Message(format!(
            "Secret file is too large: {} (maximum {} bytes)",
            path.display(),
            MAX_SECRET_FILE_SIZE
        )));
    }
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

fn password_secret(
    password: bool,
    password_file: Option<&Path>,
    confirm: bool,
) -> Result<Option<SecretString>, CliError> {
    if let Some(path) = password_file {
        return Ok(Some(SecretString::from(read_secret_file(path)?)));
    }

    if !password {
        return Ok(None);
    }

    let first = prompt_password("Enter password: ")?;
    if confirm {
        let second = prompt_password("Confirm password: ")?;
        if first != second {
            return Err(CliError::Message("Passwords do not match".to_string()));
        }
    }
    Ok(Some(SecretString::from(first)))
}

fn seed_secret(seed: bool, seed_file: Option<&Path>) -> Result<Option<SecretString>, CliError> {
    if let Some(path) = seed_file {
        return Ok(Some(SecretString::from(read_secret_file(path)?)));
    }

    if seed {
        return Ok(Some(SecretString::from(prompt_password(
            "Enter seed (pepper): ",
        )?)));
    }

    Ok(None)
}

fn parse_profile(profile: &str) -> Result<SecurityProfile, CliError> {
    match profile.to_lowercase().as_str() {
        "fast" => Ok(SecurityProfile::Fast),
        "balanced" => Ok(SecurityProfile::Balanced),
        "archive" => Ok(SecurityProfile::Archive),
        "paranoid" => Ok(SecurityProfile::Paranoid),
        "extreme" => Ok(SecurityProfile::Extreme),
        _ => Err(CliError::Message(
            "Invalid profile. Valid options: fast, balanced, archive, paranoid, extreme"
                .to_string(),
        )),
    }
}

fn profile_id(profile: SecurityProfile) -> u8 {
    match profile {
        SecurityProfile::Fast => 0,
        SecurityProfile::Balanced => 1,
        SecurityProfile::Archive => 2,
        SecurityProfile::Paranoid => 3,
        SecurityProfile::Extreme => 4,
    }
}

fn parse_padding(pad: &str) -> Result<PaddingProfile, CliError> {
    match pad.to_lowercase().as_str() {
        "none" => Ok(PaddingProfile::None),
        "bucket" => Ok(PaddingProfile::Bucket),
        s if s.starts_with("fixed:") => {
            let size_str = &s[6..];
            let size: usize = size_str.parse().map_err(|_| {
                CliError::Message(format!("Invalid fixed padding size: {size_str}"))
            })?;
            Ok(PaddingProfile::Fixed(size))
        }
        _ => Err(CliError::Message(
            "Invalid padding. Valid options: none, bucket, fixed:<SIZE>".to_string(),
        )),
    }
}

fn ensure_input_file(path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return Err(CliError::Message(format!(
            "Input file does not exist: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_distinct_file_paths(input: &Path, output: &Path) -> Result<(), CliError> {
    let same_path = if output.exists() {
        fs::canonicalize(input)? == fs::canonicalize(output)?
    } else {
        input == output
    };
    if same_path {
        return Err(CliError::Message(
            "Input and output paths must be different".to_string(),
        ));
    }
    Ok(())
}

fn ensure_output_available(path: &Path, force: bool) -> Result<(), CliError> {
    if path.exists() && !force {
        return Err(CliError::Message(format!(
            "Output file already exists: {}. Use --force to replace it.",
            path.display()
        )));
    }
    Ok(())
}

fn require_one_mode(
    password_selected: bool,
    password_file: Option<&Path>,
    key_file: bool,
    password_name: &str,
    key_name: &str,
) -> Result<(), CliError> {
    let has_password = password_selected || password_file.is_some();
    match (has_password, key_file) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => Err(CliError::Message(format!(
            "Specify either {password_name} or {key_name}"
        ))),
        (true, true) => Err(CliError::Message(format!(
            "Specify only one of {password_name} or {key_name}"
        ))),
    }
}

fn copy_exact_len(
    input: &mut dyn Read,
    output: &mut dyn Write,
    expected_len: u64,
    label: &str,
) -> Result<(), CliError> {
    let copied = io::copy(input, output)?;
    if copied != expected_len {
        return Err(CliError::Message(format!(
            "{label} changed while being copied: expected {expected_len} bytes, copied {copied}"
        )));
    }
    Ok(())
}

fn create_sfx(temp_out: &Path, out_file: &Path, force: bool) -> Result<(), CliError> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| CliError::Message("Could not locate current executable directory".into()))?
        .to_path_buf();
    let stub_path = exe_dir.join(if cfg!(windows) {
        "lvau-stub.exe"
    } else {
        "lvau-stub"
    });

    if !stub_path.exists() {
        let _ = fs::remove_file(temp_out);
        return Err(CliError::Message(format!(
            "SFX stub not found at {}. Build lvau-stub before creating SFX archives.",
            stub_path.display()
        )));
    }

    let parent = out_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let mut stub = fs::File::open(&stub_path)?;
    if !stub.metadata()?.is_file() {
        return Err(CliError::Message(format!(
            "SFX stub is not a regular file: {}",
            stub_path.display()
        )));
    }

    io::copy(&mut stub, &mut output)?;
    let mut payload = fs::File::open(temp_out)?;
    let payload_len = payload.metadata()?.len();
    copy_exact_len(&mut payload, &mut output, payload_len, "SFX payload")?;
    output.write_all(&payload_len.to_le_bytes())?;
    output.write_all(b"LVAUSFX1")?;
    output.as_file().sync_all()?;

    #[cfg(unix)]
    fs::set_permissions(output.path(), stub.metadata()?.permissions())?;

    lvau_core::crypto::output::persist_temp_path(output.into_temp_path(), out_file, force)?;

    fs::remove_file(temp_out)?;
    Ok(())
}

fn sfx_payload_temp_dir(out_file: &Path) -> Result<tempfile::TempDir, CliError> {
    let parent = out_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(tempfile::tempdir_in(parent)?)
}

fn get_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// JSON-serializable inspect result.
#[derive(Serialize)]
struct InspectResult {
    magic: String,
    version: u16,
    profile: String,
    algorithm: String,
    kdf: Option<KdfInfo>,
    recipient_count: usize,
    recipients: Vec<RecipientInfo>,
    content_type: Option<String>,
    public_label: Option<String>,
    signed: bool,
    signer_fingerprint: Option<String>,
    release_metadata: Option<lvau_protocol::envelope::ReleaseMetadata>,
    has_recovery_metadata: bool,
}

#[derive(Serialize)]
struct KdfInfo {
    algorithm: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize)]
struct RecipientInfo {
    index: usize,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sanitize an attacker-controlled public label for terminal display.
///
/// Control characters (including ESC) are replaced so a crafted capsule
/// cannot inject terminal escape sequences or forge log lines via `inspect`.
/// JSON output keeps the raw value; only human-readable text is sanitized.
fn sanitize_public_label(label: &str) -> String {
    const MAX_DISPLAY_CHARS: usize = 512;
    let mut sanitized = String::with_capacity(label.len().min(MAX_DISPLAY_CHARS));
    for ch in label.chars().take(MAX_DISPLAY_CHARS) {
        if ch.is_control() {
            sanitized.push('\u{FFFD}');
        } else {
            sanitized.push(ch);
        }
    }
    if label.chars().count() > MAX_DISPLAY_CHARS {
        sanitized.push_str("…[truncated]");
    }
    sanitized
}

fn v3_profile_name(id: u8) -> &'static str {
    match id {
        0 => "Fast",
        1 => "Balanced",
        2 => "Archive",
        3 => "Paranoid",
        4 => "Extreme",
        _ => unreachable!("validated v3 profile"),
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();

    let mut builder = env_logger::Builder::new();
    builder.filter_level(if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });
    builder.init();

    match cli.command {
        Commands::Keygen { out_base, force } => {
            let priv_path = out_base.with_extension("lvau-key");
            let pub_path = out_base.with_extension("lvau-pub");
            ensure_output_available(&priv_path, force)?;
            ensure_output_available(&pub_path, force)?;

            println!("Generating experimental X25519 + ML-KEM-768 hybrid keypair...");
            let (priv_key, pub_key) = generate_keypair();

            priv_key.save_to_file(&priv_path)?;
            pub_key.save_to_file(&pub_path)?;

            println!("Private key: {}", priv_path.display());
            println!("Public key:  {}", pub_path.display());
        }
        Commands::Encrypt {
            in_file,
            out_file,
            password,
            password_file,
            pub_key,
            recipient_group,
            profile,
            format,
            suite,
            recipient_suite,
            seed,
            seed_file,
            sfx,
            force,
            policy,
            allow_policy_override,
        } => {
            ensure_input_file(&in_file)?;
            ensure_distinct_file_paths(&in_file, &out_file)?;
            ensure_output_available(&out_file, force)?;

            let has_password = password || password_file.is_some();
            let has_pub = pub_key.is_some() || recipient_group.is_some();
            if has_password && has_pub {
                return Err(CliError::Message(format!(
                    "Cannot use {} and {} together.",
                    "--password/--password-file", "--pub-key/--recipient-group"
                )));
            }
            if !has_password && !has_pub {
                return Err(CliError::Message(format!(
                    "Must provide either {} or {}.",
                    "--password/--password-file", "--pub-key/--recipient-group"
                )));
            }

            let use_v3 = match format.to_ascii_lowercase().as_str() {
                "v2" => {
                    if suite.is_some() || recipient_suite.is_some() {
                        return Err(CliError::Message(
                            "--suite and --recipient-suite are only valid with --format v3".into(),
                        ));
                    }
                    false
                }
                "v3" => {
                    match suite.as_deref().map(str::to_ascii_lowercase).as_deref() {
                        Some("lv3-xc20p") | Some("lv3-aesgcmsiv-xc20p") => {}
                        _ => {
                            return Err(CliError::Message(
                                "Experimental v3 requires --suite lv3-xc20p or lv3-aesgcmsiv-xc20p"
                                    .into(),
                            ));
                        }
                    }
                    if seed
                        || seed_file.is_some()
                        || sfx
                        || policy.is_some()
                        || allow_policy_override
                    {
                        return Err(CliError::Message(
                            "Experimental v3 does not support seed, SFX, or policy options".into(),
                        ));
                    }
                    true
                }
                _ => {
                    return Err(CliError::Message(
                        "Invalid format. Valid options: v2, v3".into(),
                    ))
                }
            };

            if recipient_suite.is_some() && !has_pub {
                return Err(CliError::Message(
                    "--recipient-suite requires --pub-key or --recipient-group".into(),
                ));
            }
            let recipient_suite = recipient_suite.as_deref().map(str::to_ascii_lowercase);
            if let Some(value) = recipient_suite.as_deref() {
                if value != "ml-kem-768" && value != "x25519-hpke" && value != "hybrid-x25519-mlkem"
                {
                    return Err(CliError::Message(
                        "Invalid recipient suite. Valid options: ml-kem-768, x25519-hpke, hybrid-x25519-mlkem"
                            .into(),
                    ));
                }
            }
            if use_v3 && has_pub && profile.is_some() {
                return Err(CliError::Message(
                    "--profile applies to password KDFs and is not used with v3 recipient suites"
                        .into(),
                ));
            }
            if use_v3
                && has_pub
                && suite.as_deref().map(str::to_ascii_lowercase).as_deref()
                    == Some("lv3-aesgcmsiv-xc20p")
                && recipient_suite.as_deref() != Some("ml-kem-768")
                && recipient_suite.as_deref() != Some("hybrid-x25519-mlkem")
            {
                return Err(CliError::Message(
                    "The layered suite lv3-aesgcmsiv-xc20p supports password files and ML-KEM-768 (A4) recipients; X25519-HPKE (A3) stays single-layer"
                        .into(),
                ));
            }
            let sec_profile = parse_profile(profile.as_deref().unwrap_or("balanced"))?;
            let temp_dir = if sfx {
                Some(sfx_payload_temp_dir(&out_file)?)
            } else {
                None
            };
            let temp_out = temp_dir
                .as_ref()
                .map(|dir| dir.path().join("payload.lvau"))
                .unwrap_or_else(|| out_file.clone());

            let file_len = fs::metadata(&in_file).map(|m| m.len()).unwrap_or(0);
            let pb = get_progress_bar(file_len);
            let mut progress_callback = |bytes: u64| pb.set_position(bytes);

            let pol = match policy {
                Some(p) => Some(
                    lvau_core::policy::CapsulePolicy::load_from_file(&p)
                        .map_err(|e| CliError::Message(format!("Failed to load policy: {e}")))?,
                ),
                None => None,
            };

            if use_v3 && has_pub {
                let mut pubs = Vec::new();
                if let Some(pub_path) = pub_key.as_ref() {
                    pubs.push(HybridPublicKey::load_from_file(pub_path)?);
                }
                if let Some(group_path) = recipient_group.as_ref() {
                    let group = lvau_core::groups::RecipientGroup::load_from_file(group_path)
                        .map_err(CliError::Message)?;
                    pubs.extend(group.extract_public_keys()?);
                }
                if recipient_suite.as_deref() == Some("ml-kem-768")
                    || recipient_suite.as_deref() == Some("hybrid-x25519-mlkem")
                {
                    let payload_suite =
                        match suite.as_deref().map(str::to_ascii_lowercase).as_deref() {
                            Some("lv3-aesgcmsiv-xc20p") => {
                                lvau_core::crypto::suite::V3SuiteId::Aes256GcmSivXChaCha20Poly1305
                            }
                            _ => lvau_core::crypto::suite::V3SuiteId::XChaCha20Poly1305,
                        };
                    if recipient_suite.as_deref() == Some("hybrid-x25519-mlkem") {
                        lvau_core::crypto::suite::v3::mutable_file::encrypt_file_hybrid_with_suite(
                            &in_file,
                            &temp_out,
                            &pubs,
                            payload_suite,
                            !sfx && force,
                            Some(&mut progress_callback),
                        )?;
                    } else {
                        lvau_core::crypto::suite::v3::mutable_file::encrypt_file_mlkem_with_suite(
                            &in_file,
                            &temp_out,
                            &pubs,
                            payload_suite,
                            !sfx && force,
                            Some(&mut progress_callback),
                        )?;
                    }
                } else {
                    lvau_core::crypto::suite::v3::hpke_file::encrypt_file_keypairs(
                        &in_file,
                        &temp_out,
                        &pubs,
                        !sfx && force,
                        Some(&mut progress_callback),
                    )?;
                }
            } else if use_v3 {
                let pwd = password_secret(password, password_file.as_deref(), true)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let payload_suite = match suite.as_deref().map(str::to_ascii_lowercase).as_deref() {
                    Some("lv3-aesgcmsiv-xc20p") => {
                        lvau_core::crypto::suite::V3SuiteId::Aes256GcmSivXChaCha20Poly1305
                    }
                    _ => lvau_core::crypto::suite::V3SuiteId::XChaCha20Poly1305,
                };
                lvau_core::crypto::suite::v3::file::encrypt_file_password_with_suite(
                    &in_file,
                    &temp_out,
                    pwd,
                    sec_profile,
                    payload_suite,
                    !sfx && force,
                    Some(&mut progress_callback),
                )?;
            } else if pub_key.is_some() || recipient_group.is_some() {
                let mut pubs = Vec::new();
                if let Some(pub_path) = pub_key {
                    pubs.push(HybridPublicKey::load_from_file(&pub_path)?);
                }
                if let Some(group_path) = recipient_group {
                    let group = lvau_core::groups::RecipientGroup::load_from_file(&group_path)
                        .map_err(CliError::Message)?;
                    let mut group_keys = group.extract_public_keys()?;
                    pubs.append(&mut group_keys);
                }

                encrypt_file_keypairs_with_overwrite(
                    &in_file,
                    &temp_out,
                    &pubs,
                    sec_profile,
                    Some(&mut progress_callback),
                    pol.as_ref(),
                    allow_policy_override,
                    !sfx && force,
                )?;
            } else {
                let pwd = password_secret(password, password_file.as_deref(), true)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let seed_val = seed_secret(seed, seed_file.as_deref())?;
                encrypt_file_password_with_overwrite(
                    &in_file,
                    &temp_out,
                    pwd,
                    seed_val,
                    sec_profile,
                    Some(&mut progress_callback),
                    pol.as_ref(),
                    allow_policy_override,
                    !sfx && force,
                )?;
            }
            pb.finish_and_clear();

            if sfx {
                create_sfx(&temp_out, &out_file, force)?;
            }

            println!("Encrypted: {}", out_file.display());
        }
        Commands::Decrypt {
            in_file,
            out_file,
            password,
            password_file,
            priv_key,
            seed,
            seed_file,
            force,
        } => {
            ensure_input_file(&in_file)?;
            ensure_distinct_file_paths(&in_file, &out_file)?;
            ensure_output_available(&out_file, force)?;
            require_one_mode(
                password,
                password_file.as_deref(),
                priv_key.is_some(),
                "--password/--password-file",
                "--priv-key",
            )?;

            let file_len = fs::metadata(&in_file).map(|m| m.len()).unwrap_or(0);
            let pb = get_progress_bar(file_len);
            let mut progress_callback = |bytes: u64| pb.set_position(bytes);
            let is_v3 = lvau_core::crypto::suite::v3::file::is_v3_file(&in_file)?;

            if is_v3 {
                match lvau_core::crypto::suite::v3::file::file_revision(&in_file)? {
                    lvau_core::crypto::suite::v3::file::V3FileRevision::LegacyPassword => {
                        if priv_key.is_some() {
                            return Err(CliError::Message(
                                "Legacy v3 password files do not support private-key decryption"
                                    .into(),
                            ));
                        }
                        if seed || seed_file.is_some() {
                            return Err(CliError::Message(
                                "Legacy v3 password files do not support a seed".into(),
                            ));
                        }
                        let pwd = password_secret(password, password_file.as_deref(), false)?
                            .ok_or_else(|| CliError::Message("Missing password".into()))?;
                        lvau_core::crypto::suite::v3::file::decrypt_file_password(
                            &in_file,
                            &out_file,
                            pwd,
                            force,
                            Some(&mut progress_callback),
                        )?;
                    }
                    lvau_core::crypto::suite::v3::file::V3FileRevision::HpkeRecipients => {
                        if password || password_file.is_some() {
                            return Err(CliError::Message(
                                "This v3 recipient file requires --priv-key".into(),
                            ));
                        }
                        if seed || seed_file.is_some() {
                            return Err(CliError::Message(
                                "v3 HPKE recipient files do not support a seed".into(),
                            ));
                        }
                        let private_path = priv_key.as_ref().ok_or_else(|| {
                            CliError::Message(
                                "Missing --priv-key for v3 HPKE recipient file".into(),
                            )
                        })?;
                        let private_key = HybridPrivateKey::load_from_file(private_path)?;
                        lvau_core::crypto::suite::v3::hpke_file::decrypt_file_keypair(
                            &in_file,
                            &out_file,
                            &private_key,
                            force,
                            Some(&mut progress_callback),
                        )?;
                    }
                    lvau_core::crypto::suite::v3::file::V3FileRevision::MutableSlots => {
                        if seed || seed_file.is_some() {
                            return Err(CliError::Message(
                                "v3 mutable files do not support a seed".into(),
                            ));
                        }
                        if password || password_file.is_some() {
                            let pwd =
                                password_secret(password, password_file.as_deref(), false)?
                                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                            lvau_core::crypto::suite::v3::mutable_file::decrypt_file_password(
                                &in_file,
                                &out_file,
                                pwd,
                                force,
                                Some(&mut progress_callback),
                            )?;
                        } else {
                            let private_key =
                                HybridPrivateKey::load_from_file(priv_key.as_ref().ok_or_else(
                                    || CliError::Message("Missing --priv-key".into()),
                                )?)?;
                            lvau_core::crypto::suite::v3::mutable_file::decrypt_file_keypair(
                                &in_file,
                                &out_file,
                                &private_key,
                                force,
                                Some(&mut progress_callback),
                            )?;
                        }
                    }
                }
            } else if let Some(priv_path) = priv_key {
                let pk = HybridPrivateKey::load_from_file(&priv_path)?;
                decrypt_file_keypair_with_overwrite(
                    &in_file,
                    &out_file,
                    &pk,
                    Some(&mut progress_callback),
                    force,
                )?;
            } else {
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let seed_val = seed_secret(seed, seed_file.as_deref())?;
                decrypt_file_password_with_overwrite(
                    &in_file,
                    &out_file,
                    pwd,
                    seed_val,
                    Some(&mut progress_callback),
                    force,
                )?;
            }
            pb.finish_and_clear();

            println!("Decrypted: {}", out_file.display());
        }
        Commands::Inspect { in_file, json } => {
            ensure_input_file(&in_file)?;

            let is_v3 = lvau_core::crypto::suite::v3::file::is_v3_file(&in_file)?;
            if is_v3
                && lvau_core::crypto::suite::v3::file::file_revision(&in_file)?
                    == lvau_core::crypto::suite::v3::file::V3FileRevision::HpkeRecipients
            {
                let info = lvau_core::crypto::suite::v3::hpke_file::inspect_file(&in_file)?;
                let recipients = info
                    .envelope
                    .recipients
                    .iter()
                    .enumerate()
                    .map(|(index, recipient)| RecipientInfo {
                        index,
                        kind: "X25519-HPKE".into(),
                        key_id: Some(hex_encode(&recipient.key_id)),
                    })
                    .collect::<Vec<_>>();
                if json {
                    let result = InspectResult {
                        magic: "LVAU".into(),
                        version: 3,
                        profile: "Not applicable (HPKE)".into(),
                        algorithm: "LV3-XC20P".into(),
                        kdf: None,
                        recipient_count: recipients.len(),
                        recipients,
                        content_type: Some("SingleFile".into()),
                        public_label: None,
                        signed: false,
                        signer_fingerprint: None,
                        release_metadata: None,
                        has_recovery_metadata: false,
                    };
                    output::print_success("inspect", &result)?;
                } else {
                    println!("Lvau envelope metadata");
                    println!("Magic:     LVAU");
                    println!("Version:   3, envelope revision A3 (experimental)");
                    println!("Payload:   LV3-XC20P");
                    println!(
                        "Recipient suite: HPKE Base (X25519 / HKDF-SHA256 / ChaCha20Poly1305)"
                    );
                    for (index, recipient) in info.envelope.recipients.iter().enumerate() {
                        println!(
                            "  Recipient[{index}] key ID: {} (public identifier; not identity proof)",
                            hex_encode(&recipient.key_id)
                        );
                    }
                    println!("Content:   SingleFile");
                    println!("Signed:    no");
                }
                return Ok(());
            }

            if is_v3
                && lvau_core::crypto::suite::v3::file::file_revision(&in_file)?
                    == lvau_core::crypto::suite::v3::file::V3FileRevision::MutableSlots
            {
                let info = lvau_core::crypto::suite::v3::mutable_file::inspect_file(&in_file)?;
                let suite_name = lvau_core::crypto::suite::v3::file::payload_suite_name(
                    lvau_core::crypto::suite::v3::file::suite_from_id(
                        info.envelope.payload_suite_id,
                    )?,
                );
                let password_profile_id = info.envelope.slots.iter().find_map(|slot| match slot {
                    lvau_protocol::envelope_v3::V3MutableSlot::Password(slot) => {
                        Some(slot.profile_id)
                    }
                    _ => None,
                });
                let profile = password_profile_id
                    .map(v3_profile_name)
                    .unwrap_or("Not applicable (recipient-only)");
                let kdf = info
                    .password_kdf_costs
                    .map(|(m_cost, t_cost, p_cost)| KdfInfo {
                        algorithm: "Argon2id".into(),
                        m_cost,
                        t_cost,
                        p_cost,
                    });
                let recipients = info
                    .envelope
                    .slots
                    .iter()
                    .enumerate()
                    .map(|(index, slot)| match slot {
                        lvau_protocol::envelope_v3::V3MutableSlot::Password(_) => RecipientInfo {
                            index,
                            kind: "Password".into(),
                            key_id: None,
                        },
                        lvau_protocol::envelope_v3::V3MutableSlot::X25519Hpke(slot) => {
                            RecipientInfo {
                                index,
                                kind: "X25519-HPKE".into(),
                                key_id: Some(hex_encode(&slot.key_id)),
                            }
                        }
                        lvau_protocol::envelope_v3::V3MutableSlot::MlKem768(slot) => {
                            RecipientInfo {
                                index,
                                kind: "ML-KEM-768".into(),
                                key_id: Some(hex_encode(&slot.key_id)),
                            }
                        }
                        lvau_protocol::envelope_v3::V3MutableSlot::HybridX25519MlKem768(slot) => {
                            RecipientInfo {
                                index,
                                kind: "Hybrid-X25519-MLKEM".into(),
                                key_id: Some(hex_encode(&slot.key_id)),
                            }
                        }
                    })
                    .collect::<Vec<_>>();
                if json {
                    let result = InspectResult {
                        magic: "LVAU".into(),
                        version: 3,
                        profile: profile.into(),
                        algorithm: suite_name.into(),
                        kdf,
                        recipient_count: recipients.len(),
                        recipients,
                        content_type: Some("SingleFile".into()),
                        public_label: None,
                        signed: false,
                        signer_fingerprint: None,
                        release_metadata: None,
                        has_recovery_metadata: false,
                    };
                    output::print_success("inspect", &result)?;
                } else {
                    println!("Lvau envelope metadata");
                    println!("Magic:     LVAU");
                    println!("Version:   3, envelope revision A4 (experimental)");
                    println!("Payload:   {suite_name}");
                    println!("Profile:   {profile}");
                    if let Some((m_cost, t_cost, p_cost)) = info.password_kdf_costs {
                        println!("KDF:       Argon2id (m={m_cost} KiB, t={t_cost}, p={p_cost})");
                    }
                    println!("Slots:     {}", recipients.len());
                    for recipient in recipients {
                        match recipient.key_id {
                            Some(key_id) => println!(
                                "  [{}] {} key ID: {} (public identifier; not identity proof)",
                                recipient.index, recipient.kind, key_id
                            ),
                            None => println!("  [{}] {}", recipient.index, recipient.kind),
                        }
                    }
                    println!("Content:   SingleFile");
                    println!("Signed:    no");
                }
                return Ok(());
            }

            if is_v3 {
                let info = lvau_core::crypto::suite::v3::file::inspect_file(&in_file)?;
                let suite_name = lvau_core::crypto::suite::v3::file::payload_suite_name(
                    lvau_core::crypto::suite::v3::file::suite_from_id(info.envelope.suite_id)?,
                );
                let profile = match info.envelope.profile_id {
                    0 => "Fast",
                    1 => "Balanced",
                    2 => "Archive",
                    3 => "Paranoid",
                    4 => "Extreme",
                    _ => unreachable!("validated v3 profile"),
                };
                if json {
                    let result = InspectResult {
                        magic: "LVAU".into(),
                        version: 3,
                        profile: profile.into(),
                        algorithm: suite_name.into(),
                        kdf: Some(KdfInfo {
                            algorithm: "Argon2id".into(),
                            m_cost: info.m_cost,
                            t_cost: info.t_cost,
                            p_cost: info.p_cost,
                        }),
                        recipient_count: 1,
                        recipients: vec![RecipientInfo {
                            index: 0,
                            kind: "Password".into(),
                            key_id: None,
                        }],
                        content_type: Some("SingleFile".into()),
                        public_label: None,
                        signed: false,
                        signer_fingerprint: None,
                        release_metadata: None,
                        has_recovery_metadata: false,
                    };
                    output::print_success("inspect", &result)?;
                } else {
                    println!("Lvau envelope metadata");
                    println!("Magic:     LVAU");
                    println!("Version:   3 (experimental)");
                    println!("Profile:   {profile}");
                    println!("Algorithm: {suite_name}");
                    println!(
                        "KDF:       Argon2id (m={} KiB, t={}, p={})",
                        info.m_cost, info.t_cost, info.p_cost
                    );
                    println!("Recipients: 1");
                    println!("  [0] Password (root key wrapped)");
                    println!("Content:   SingleFile");
                    println!("Signed:    no");
                }
                return Ok(());
            }

            let envelope = lvau_core::crypto::read_envelope_from_path(&in_file)?;

            let header = &envelope.header;
            let sig_fingerprint = envelope
                .signature
                .as_ref()
                .map(|s| hex_encode(&s.signer_fingerprint));

            if json {
                let result = InspectResult {
                    magic: std::str::from_utf8(&header.magic)
                        .unwrap_or("????")
                        .to_string(),
                    version: header.version,
                    profile: format!("{:?}", header.profile),
                    algorithm: format!("{:?}", header.algorithm),
                    kdf: header.kdf.as_ref().map(
                        |KdfParams::Argon2id {
                             m_cost,
                             t_cost,
                             p_cost,
                             ..
                         }| KdfInfo {
                            algorithm: "Argon2id".to_string(),
                            m_cost: *m_cost,
                            t_cost: *t_cost,
                            p_cost: *p_cost,
                        },
                    ),
                    recipient_count: header.recipients.len(),
                    recipients: header
                        .recipients
                        .iter()
                        .enumerate()
                        .map(|(i, r)| RecipientInfo {
                            index: i,
                            kind: match r {
                                Recipient::Password { .. } => "Password".to_string(),
                                Recipient::X25519MlkemHybrid { .. } => {
                                    "X25519+ML-KEM-768".to_string()
                                }
                            },
                            key_id: None,
                        })
                        .collect(),
                    content_type: envelope.content_type.as_ref().map(|ct| format!("{ct:?}")),
                    public_label: envelope.public_label.clone(),
                    signed: envelope.signature.is_some(),
                    signer_fingerprint: sig_fingerprint.clone(),
                    release_metadata: envelope.release_metadata.clone(),
                    has_recovery_metadata: envelope.recovery_metadata.is_some(),
                };
                output::print_success("inspect", &result)?;
            } else {
                println!("Lvau envelope metadata");
                println!(
                    "Magic:     {}",
                    std::str::from_utf8(&header.magic).unwrap_or("????")
                );
                println!("Version:   {}", header.version);
                println!("Profile:   {:?}", header.profile);
                println!("Algorithm: {:?}", header.algorithm);
                match &header.kdf {
                    Some(KdfParams::Argon2id {
                        m_cost,
                        t_cost,
                        p_cost,
                        ..
                    }) => {
                        println!(
                            "KDF:       Argon2id (m={} KiB, t={}, p={})",
                            m_cost, t_cost, p_cost
                        );
                    }
                    None => {
                        println!("KDF:       None (keypair-based)");
                    }
                }
                println!("Recipients: {}", header.recipients.len());
                for (i, recipient) in header.recipients.iter().enumerate() {
                    match recipient {
                        Recipient::Password { .. } => println!("  [{i}] Password (FEK wrapped)"),
                        Recipient::X25519MlkemHybrid { .. } => {
                            println!("  [{i}] X25519 + ML-KEM-768 hybrid")
                        }
                    }
                }
                if let Some(ct) = &envelope.content_type {
                    println!("Content:   {ct:?}");
                }
                if let Some(label) = &envelope.public_label {
                    println!("Label:     {}", sanitize_public_label(label));
                }
                if envelope.signature.is_some() {
                    println!("Signed:    yes");
                    if let Some(fp) = &sig_fingerprint {
                        println!("Signer:    {fp}");
                    }
                } else {
                    println!("Signed:    no");
                }

                if let Some(rm) = &envelope.release_metadata {
                    println!("Release Metadata:");
                    if let Some(proj) = &rm.project_name {
                        println!("  Project: {}", proj);
                    }
                    if let Some(ver) = &rm.version {
                        println!("  Version: {}", ver);
                    }
                    if let Some(git) = &rm.git_commit {
                        println!("  Commit:  {}", git);
                    }
                    if let Some(ts) = &rm.build_timestamp {
                        println!("  Built:   {}", ts);
                    }
                }
                if envelope.recovery_metadata.is_some() {
                    println!("Recovery Metadata: Present");
                }
            }
        }
        Commands::Verify {
            in_file,
            password,
            password_file,
            priv_key,
            seed,
            seed_file,
            json,
        } => {
            ensure_input_file(&in_file)?;
            require_one_mode(
                password,
                password_file.as_deref(),
                priv_key.is_some(),
                "--password/--password-file",
                "--priv-key",
            )?;

            let file_len = fs::metadata(&in_file).map(|m| m.len()).unwrap_or(0);
            let pb = get_progress_bar(file_len);
            let mut progress_callback = |bytes: u64| pb.set_position(bytes);
            let is_v3 = lvau_core::crypto::suite::v3::file::is_v3_file(&in_file)?;

            if is_v3 {
                match lvau_core::crypto::suite::v3::file::file_revision(&in_file)? {
                    lvau_core::crypto::suite::v3::file::V3FileRevision::LegacyPassword => {
                        if priv_key.is_some() {
                            return Err(CliError::Message(
                                "Legacy v3 password files do not support private-key verification"
                                    .into(),
                            ));
                        }
                        if seed || seed_file.is_some() {
                            return Err(CliError::Message(
                                "Legacy v3 password files do not support a seed".into(),
                            ));
                        }
                        let pwd = password_secret(password, password_file.as_deref(), false)?
                            .ok_or_else(|| CliError::Message("Missing password".into()))?;
                        lvau_core::crypto::suite::v3::file::verify_file_password(
                            &in_file,
                            pwd,
                            Some(&mut progress_callback),
                        )?;
                    }
                    lvau_core::crypto::suite::v3::file::V3FileRevision::HpkeRecipients => {
                        if password || password_file.is_some() {
                            return Err(CliError::Message(
                                "This v3 recipient file requires --priv-key".into(),
                            ));
                        }
                        if seed || seed_file.is_some() {
                            return Err(CliError::Message(
                                "v3 HPKE recipient files do not support a seed".into(),
                            ));
                        }
                        let private_path = priv_key.as_ref().ok_or_else(|| {
                            CliError::Message(
                                "Missing --priv-key for v3 HPKE recipient file".into(),
                            )
                        })?;
                        let private_key = HybridPrivateKey::load_from_file(private_path)?;
                        lvau_core::crypto::suite::v3::hpke_file::verify_file_keypair(
                            &in_file,
                            &private_key,
                            Some(&mut progress_callback),
                        )?;
                    }
                    lvau_core::crypto::suite::v3::file::V3FileRevision::MutableSlots => {
                        if seed || seed_file.is_some() {
                            return Err(CliError::Message(
                                "v3 mutable files do not support a seed".into(),
                            ));
                        }
                        if password || password_file.is_some() {
                            let pwd =
                                password_secret(password, password_file.as_deref(), false)?
                                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                            lvau_core::crypto::suite::v3::mutable_file::verify_file_password(
                                &in_file,
                                pwd,
                                Some(&mut progress_callback),
                            )?;
                        } else {
                            let private_key =
                                HybridPrivateKey::load_from_file(priv_key.as_ref().ok_or_else(
                                    || CliError::Message("Missing --priv-key".into()),
                                )?)?;
                            lvau_core::crypto::suite::v3::mutable_file::verify_file_keypair(
                                &in_file,
                                &private_key,
                                Some(&mut progress_callback),
                            )?;
                        }
                    }
                }
            } else if let Some(priv_path) = priv_key {
                let pk = HybridPrivateKey::load_from_file(&priv_path)?;
                verify_file_keypair(&in_file, &pk, Some(&mut progress_callback))?;
            } else {
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let seed_val = seed_secret(seed, seed_file.as_deref())?;
                verify_file_password(&in_file, pwd, seed_val, Some(&mut progress_callback))?;
            }
            pb.finish_and_clear();

            if json {
                output::print_success("verify", &serde_json::json!({ "file": in_file }))?;
            } else {
                println!("Verification successful: {}", in_file.display());
            }
        }
        Commands::Preflight {
            in_file,
            verify_key,
            policy,
            json,
        } => {
            ensure_input_file(&in_file)?;

            let mut vkey = None;
            if let Some(vk_path) = verify_key {
                let key = lvau_core::signing::load_verify_key(&vk_path)?;
                vkey = Some(key);
            }

            let pol = match policy {
                Some(p) => Some(
                    lvau_core::policy::CapsulePolicy::load_from_file(&p)
                        .map_err(|e| CliError::Message(format!("Failed to load policy: {e}")))?,
                ),
                None => None,
            };

            let res = lvau_core::preflight::run_preflight(&in_file, vkey.as_ref(), pol.as_ref());
            let failed = matches!(res.status, lvau_core::preflight::PreflightStatus::Fail);

            if json {
                output::print_success("preflight", &res)?;
            } else {
                println!("Preflight Report for: {}", in_file.display());
                println!("===========================================");
                println!("Status: {:?}", res.status);
                println!("Parse OK: {}", res.parse_ok);
                if let Some(err) = res.parse_error {
                    println!("Parse Error: {}", err);
                }
                if res.parse_ok {
                    println!("Version: {}", res.version);
                    println!("Content Type: {}", res.content_type);
                    println!("Security Profile: {}", res.profile);
                    println!("Algorithm: {}", res.algorithm);
                    println!("Recipient Slots: {}", res.recipient_count);
                    println!("Public Hash OK: {}", res.public_hash_ok);
                    println!("Signature Present: {}", res.signature_present);
                    if let Some(fp) = res.signer_fingerprint {
                        println!("Signer Fingerprint: {}", fp);
                    }
                    if let Some(v) = res.signature_valid {
                        println!("Signature Valid: {}", v);
                    }
                    println!("Has Recovery Metadata: {}", res.has_recovery_metadata);
                    println!("Has Release Metadata: {}", res.has_release_metadata);
                    println!("Policy Overridden: {}", res.policy_overridden);
                    if let Some(p) = res.policy_ok {
                        println!("Policy Checked: {}", if p { "PASS" } else { "FAIL" });
                    }
                    if !res.experimental_flags.is_empty() {
                        println!("Experimental Flags: {}", res.experimental_flags.join(", "));
                    }
                    if !res.approvals.is_empty() {
                        println!("Approvals ({} seals):", res.approvals.len());
                        for app in res.approvals {
                            println!("- {}", app);
                        }
                    }
                }

                if !res.errors.is_empty() {
                    println!("\nErrors:");
                    for e in res.errors {
                        println!("- [ERROR] {}", e);
                    }
                }
                if !res.warnings.is_empty() {
                    println!("\nWarnings:");
                    for w in res.warnings {
                        println!("- [WARN]  {}", w);
                    }
                }
                if !res.policy_violations.is_empty() {
                    println!("\nPolicy Violations:");
                    for v in res.policy_violations {
                        println!("- [FAIL]  {}", v);
                    }
                }
                if !res.policy_warnings.is_empty() {
                    println!("\nPolicy Warnings:");
                    for w in res.policy_warnings {
                        println!("- [WARN]  {}", w);
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
        Commands::Report {
            in_file,
            verify_key,
            policy,
            password,
            password_file,
            priv_key,
            json,
        } => {
            ensure_input_file(&in_file)?;
            let mut vkey = None;
            if let Some(vk_path) = verify_key {
                let key = lvau_core::signing::load_verify_key(&vk_path)?;
                vkey = Some(key);
            }
            let pol = match policy {
                Some(p) => Some(
                    lvau_core::policy::CapsulePolicy::load_from_file(&p)
                        .map_err(|e| CliError::Message(format!("Failed to load policy: {e}")))?,
                ),
                None => None,
            };

            let mut cred = None;
            if let Some(pk_path) = priv_key {
                let pk = HybridPrivateKey::load_from_file(&pk_path)?;
                cred = Some(lvau_core::report::DecryptCredential::Keypair(pk));
            } else if password || password_file.is_some() {
                if let Some(pwd) = password_secret(password, password_file.as_deref(), false)? {
                    cred = Some(lvau_core::report::DecryptCredential::Password(pwd, None));
                }
            }

            let report = lvau_core::report::generate_report(
                &in_file,
                vkey.as_ref(),
                pol.as_ref(),
                cred.as_ref(),
            );

            if json {
                output::print_success("report", &report)?;
            } else {
                println!("==================================================");
                println!("             Lvau Verification Report             ");
                println!("==================================================");
                println!("File: {}", report.file_path);
                println!("Time: {}", report.timestamp);
                println!("\n--- Preflight Summary ---");
                println!("Version: {}", report.preflight.version);
                println!("Content: {}", report.preflight.content_type);
                println!("Profile: {}", report.preflight.profile);
                println!("Valid Signature: {:?}", report.preflight.signature_valid);
                println!("Policy OK: {:?}", report.preflight.policy_ok);

                println!("\n--- Decryption Check ---");
                if let Some(ok) = report.decryption_successful {
                    if ok {
                        println!("Status: SUCCESS");
                        if let Some(count) = report.file_count {
                            println!("Extracted Files: {}", count);
                        }
                    } else {
                        println!("Status: FAILED (Invalid key/password or tampered payload)");
                    }
                } else {
                    println!("Status: SKIPPED (No credentials provided)");
                }

                if !report.preflight.errors.is_empty() {
                    println!("\n--- Errors ---");
                    for err in &report.preflight.errors {
                        println!("- {}", err);
                    }
                }
                if !report.preflight.warnings.is_empty() {
                    println!("\n--- Warnings ---");
                    for warn in &report.preflight.warnings {
                        println!("- {}", warn);
                    }
                }
                println!("==================================================");
            }
        }
        Commands::Policy { action } => match action {
            PolicyAction::Inspect { in_file } => {
                let pol = lvau_core::policy::CapsulePolicy::load_from_file(&in_file)
                    .map_err(|e| CliError::Message(format!("Failed to load policy: {e}")))?;
                println!("Policy File: {}", in_file.display());
                println!("{}", toml::to_string_pretty(&pol).unwrap());
            }
            PolicyAction::Lint {
                in_file,
                policy,
                json,
            } => {
                let pol = lvau_core::policy::CapsulePolicy::load_from_file(&policy)
                    .map_err(|e| CliError::Message(format!("Failed to load policy: {e}")))?;
                let envelope = lvau_core::crypto::read_envelope_from_path(&in_file)?;

                let result = lvau_core::policy::lint_envelope(&envelope, &pol);
                let valid = result.is_valid();

                if json {
                    let json_val = serde_json::json!({
                        "valid": valid,
                        "violations": result.violations.iter().map(|v| serde_json::json!({ "rule": v.rule, "message": v.message })).collect::<Vec<_>>(),
                        "warnings": result.warnings.iter().map(|v| serde_json::json!({ "rule": v.rule, "message": v.message })).collect::<Vec<_>>()
                    });
                    output::print_success("policy.lint", &json_val)?;
                } else {
                    println!(
                        "Linting artifact {} against {}",
                        in_file.display(),
                        policy.display()
                    );
                    if result.is_valid() {
                        println!("Result: PASS");
                    } else {
                        println!("Result: FAIL");
                        for v in result.violations {
                            println!("- [VIOLATION] {}: {}", v.rule, v.message);
                        }
                    }
                    for w in result.warnings {
                        println!("- [WARNING] {}: {}", w.rule, w.message);
                    }
                }
                if !valid {
                    std::process::exit(1);
                }
            }
            PolicyAction::Create { out_file, force } => {
                ensure_output_available(&out_file, force)?;
                let pol = lvau_core::policy::CapsulePolicy::default();
                pol.save_to_file(&out_file)
                    .map_err(|e| CliError::Message(format!("Failed to save policy: {e}")))?;
                println!("Created default policy at {}", out_file.display());
            }
        },
        Commands::Rekey { action } => match action {
            RekeyAction::AddRecipient {
                in_file,
                out_file,
                password,
                password_file,
                priv_key,
                pub_key,
                recipient_suite,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_distinct_file_paths(&in_file, &out_file)?;
                ensure_output_available(&out_file, force)?;
                require_one_mode(
                    password,
                    password_file.as_deref(),
                    priv_key.is_some(),
                    "--password/--password-file",
                    "--priv-key",
                )?;
                let password = password_secret(password, password_file.as_deref(), false)?;
                let private_key = priv_key
                    .as_deref()
                    .map(HybridPrivateKey::load_from_file)
                    .transpose()?;
                let public_key = HybridPublicKey::load_from_file(&pub_key)?;
                match recipient_suite.to_ascii_lowercase().as_str() {
                    "ml-kem-768" => {
                        if let Some(private_key) = private_key.as_ref() {
                            lvau_core::crypto::suite::v3::rekey_file::add_mlkem_recipient_with_keypair(
                                &in_file, &out_file, private_key, &public_key, force,
                            )?;
                        } else {
                            lvau_core::crypto::suite::v3::rekey_file::add_mlkem_recipient(
                                &in_file,
                                &out_file,
                                password.unwrap(),
                                &public_key,
                                force,
                            )?;
                        }
                    }
                    "x25519-hpke" => {
                        if let Some(private_key) = private_key.as_ref() {
                            lvau_core::crypto::suite::v3::rekey_file::add_x25519_recipient_with_keypair(
                                &in_file, &out_file, private_key, &public_key, force,
                            )?;
                        } else {
                            lvau_core::crypto::suite::v3::rekey_file::add_x25519_recipient(
                                &in_file,
                                &out_file,
                                password.unwrap(),
                                &public_key,
                                force,
                            )?;
                        }
                    }
                    "hybrid-x25519-mlkem" => {
                        if let Some(private_key) = private_key.as_ref() {
                            lvau_core::crypto::suite::v3::rekey_file::add_hybrid_recipient_with_keypair(
                                &in_file, &out_file, private_key, &public_key, force,
                            )?;
                        } else {
                            lvau_core::crypto::suite::v3::rekey_file::add_hybrid_recipient(
                                &in_file,
                                &out_file,
                                password.unwrap(),
                                &public_key,
                                force,
                            )?;
                        }
                    }
                    _ => {
                        return Err(CliError::Message(
                            "Invalid recipient suite. Valid options: ml-kem-768, x25519-hpke, hybrid-x25519-mlkem"
                                .into(),
                        ))
                    }
                }
                println!("Recipient added: {}", out_file.display());
            }
            RekeyAction::RemoveRecipient {
                in_file,
                out_file,
                password,
                password_file,
                priv_key,
                pub_key,
                recipient_suite,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_distinct_file_paths(&in_file, &out_file)?;
                ensure_output_available(&out_file, force)?;
                require_one_mode(
                    password,
                    password_file.as_deref(),
                    priv_key.is_some(),
                    "--password/--password-file",
                    "--priv-key",
                )?;
                let password = password_secret(password, password_file.as_deref(), false)?;
                let private_key = priv_key
                    .as_deref()
                    .map(HybridPrivateKey::load_from_file)
                    .transpose()?;
                let public_key = HybridPublicKey::load_from_file(&pub_key)?;
                match recipient_suite.to_ascii_lowercase().as_str() {
                    "ml-kem-768" => {
                        if let Some(private_key) = private_key.as_ref() {
                            lvau_core::crypto::suite::v3::rekey_file::remove_mlkem_recipient_with_keypair(
                                &in_file, &out_file, private_key, &public_key, force,
                            )?;
                        } else {
                            lvau_core::crypto::suite::v3::rekey_file::remove_mlkem_recipient(
                                &in_file,
                                &out_file,
                                password.unwrap(),
                                &public_key,
                                force,
                            )?;
                        }
                    }
                    "x25519-hpke" => {
                        if let Some(private_key) = private_key.as_ref() {
                            lvau_core::crypto::suite::v3::rekey_file::remove_x25519_recipient_with_keypair(
                                &in_file, &out_file, private_key, &public_key, force,
                            )?;
                        } else {
                            lvau_core::crypto::suite::v3::rekey_file::remove_x25519_recipient(
                                &in_file,
                                &out_file,
                                password.unwrap(),
                                &public_key,
                                force,
                            )?;
                        }
                    }
                    "hybrid-x25519-mlkem" => {
                        if let Some(private_key) = private_key.as_ref() {
                            lvau_core::crypto::suite::v3::rekey_file::remove_hybrid_recipient_with_keypair(
                                &in_file, &out_file, private_key, &public_key, force,
                            )?;
                        } else {
                            lvau_core::crypto::suite::v3::rekey_file::remove_hybrid_recipient(
                                &in_file,
                                &out_file,
                                password.unwrap(),
                                &public_key,
                                force,
                            )?;
                        }
                    }
                    _ => {
                        return Err(CliError::Message(
                            "Invalid recipient suite. Valid options: ml-kem-768, x25519-hpke, hybrid-x25519-mlkem"
                                .into(),
                        ))
                    }
                }
                println!("Recipient removed: {}", out_file.display());
            }
            RekeyAction::ChangePassword {
                in_file,
                out_file,
                password,
                password_file,
                priv_key,
                new_password,
                new_password_file,
                profile,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_distinct_file_paths(&in_file, &out_file)?;
                ensure_output_available(&out_file, force)?;
                require_one_mode(
                    password,
                    password_file.as_deref(),
                    priv_key.is_some(),
                    "--password/--password-file",
                    "--priv-key",
                )?;
                let old_password = password_secret(password, password_file.as_deref(), false)?;
                let private_key = priv_key
                    .as_deref()
                    .map(HybridPrivateKey::load_from_file)
                    .transpose()?;
                let new_password = password_secret(
                    new_password,
                    new_password_file.as_deref(),
                    true,
                )?
                .ok_or_else(|| {
                    CliError::Message("Provide --new-password or --new-password-file".into())
                })?;
                let profile = profile
                    .as_deref()
                    .map(parse_profile)
                    .transpose()?
                    .map(profile_id);
                if let Some(private_key) = private_key.as_ref() {
                    lvau_core::crypto::suite::v3::rekey_file::change_password_with_keypair(
                        &in_file,
                        &out_file,
                        private_key,
                        new_password,
                        profile,
                        force,
                    )?;
                } else {
                    lvau_core::crypto::suite::v3::rekey_file::change_password(
                        &in_file,
                        &out_file,
                        old_password.unwrap(),
                        new_password,
                        profile,
                        force,
                    )?;
                }
                println!("Password changed: {}", out_file.display());
            }
            RekeyAction::ConvertA3 {
                in_file,
                out_file,
                priv_key,
                recipient_group,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_distinct_file_paths(&in_file, &out_file)?;
                ensure_output_available(&out_file, force)?;
                let source_private_key = HybridPrivateKey::load_from_file(&priv_key)?;
                let mut recipients = Vec::new();
                if let Some(group_path) = recipient_group {
                    let group = lvau_core::groups::RecipientGroup::load_from_file(&group_path)
                        .map_err(CliError::Message)?;
                    recipients = group.extract_public_keys()?;
                }
                lvau_core::crypto::suite::v3::convert_file::convert_a3_to_a4(
                    &in_file,
                    &out_file,
                    &source_private_key,
                    &recipients,
                    force,
                )?;
                println!("Converted A3 to A4: {}", out_file.display());
            }
            RekeyAction::RotateRoot {
                in_file,
                out_file,
                password,
                password_file,
                new_password,
                new_password_file,
                profile,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_distinct_file_paths(&in_file, &out_file)?;
                ensure_output_available(&out_file, force)?;
                if !lvau_core::crypto::suite::v3::file::is_v3_file(&in_file)? {
                    return Err(CliError::Message(
                        "rotate-root currently supports password-protected v3 files only".into(),
                    ));
                }
                if lvau_core::crypto::suite::v3::file::file_revision(&in_file)?
                    != lvau_core::crypto::suite::v3::file::V3FileRevision::LegacyPassword
                {
                    return Err(CliError::Message(
                        "rotate-root currently supports legacy password-v3 files only".into(),
                    ));
                }
                let old_password = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| {
                        CliError::Message(
                            "Provide --password or --password-file for the current password".into(),
                        )
                    })?;
                let new_password = password_secret(
                    new_password,
                    new_password_file.as_deref(),
                    true,
                )?
                .ok_or_else(|| {
                    CliError::Message("Provide --new-password or --new-password-file".into())
                })?;

                lvau_core::crypto::suite::v3::file::rotate_root_password(
                    &in_file,
                    &out_file,
                    old_password,
                    new_password,
                    parse_profile(&profile)?,
                    force,
                    None,
                )?;
                println!("Root key rotated: {}", out_file.display());
                eprintln!(
                    "Existing copies of the input are unchanged and remain decryptable with their previous credentials."
                );
            }
        },
        Commands::Bundle { action } => match action {
            BundleAction::Pack {
                in_dir,
                out_file,
                password,
                password_file,
                recipient_group,
                profile,
                allow_symlinks,
                metadata_profile: _,
                pad,
                public_label: _,
                force,
                policy,
                allow_policy_override,
            } => {
                if !in_dir.is_dir() {
                    return Err(CliError::Message(format!(
                        "Input directory does not exist: {}",
                        in_dir.display()
                    )));
                }
                ensure_output_available(&out_file, force)?;

                let has_password = password || password_file.is_some();
                let has_pub = recipient_group.is_some();
                if has_password && has_pub {
                    return Err(CliError::Message(format!(
                        "Cannot use {} and {} together.",
                        "--password/--password-file", "--recipient-group"
                    )));
                }
                if !has_password && !has_pub {
                    return Err(CliError::Message(format!(
                        "Must provide either {} or {}.",
                        "--password/--password-file", "--recipient-group"
                    )));
                }

                let credential = if let Some(group_path) = recipient_group {
                    let group = lvau_core::groups::RecipientGroup::load_from_file(&group_path)
                        .map_err(CliError::Message)?;
                    let group_keys = group.extract_public_keys()?;
                    lvau_core::crypto::EncryptCredential::Keypairs(group_keys)
                } else {
                    let pwd = password_secret(password, password_file.as_deref(), true)?
                        .ok_or_else(|| CliError::Message("Missing password".into()))?;
                    lvau_core::crypto::EncryptCredential::Password(pwd, None)
                };

                let sec_profile = parse_profile(&profile)?;
                let padding = parse_padding(&pad)?;

                let pol = match policy {
                    Some(p) => Some(
                        lvau_core::policy::CapsulePolicy::load_from_file(&p).map_err(|e| {
                            CliError::Message(format!("Failed to load policy: {e}"))
                        })?,
                    ),
                    None => None,
                };

                let manifest = pack_directory(
                    &in_dir,
                    &out_file,
                    credential,
                    sec_profile,
                    allow_symlinks,
                    &padding,
                    force,
                    pol.as_ref(),
                    allow_policy_override,
                )?;

                println!(
                    "Bundle created: {} ({} files)",
                    out_file.display(),
                    manifest.entries.len()
                );
            }
            BundleAction::Inspect { in_file, json } => {
                ensure_input_file(&in_file)?;
                let (header, content_type, public_label) = inspect_bundle(&in_file)?;

                if json {
                    let result = serde_json::json!({
                        "magic": std::str::from_utf8(&header.magic).unwrap_or("????"),
                        "version": header.version,
                        "profile": format!("{:?}", header.profile),
                        "algorithm": format!("{:?}", header.algorithm),
                        "content_type": content_type.map(|ct| format!("{ct:?}")),
                        "public_label": public_label,
                    });
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                } else {
                    println!("Bundle envelope metadata");
                    println!(
                        "Magic:     {}",
                        std::str::from_utf8(&header.magic).unwrap_or("????")
                    );
                    println!("Version:   {}", header.version);
                    println!("Profile:   {:?}", header.profile);
                    println!("Algorithm: {:?}", header.algorithm);
                    if let Some(ct) = content_type {
                        println!("Content:   {ct:?}");
                    }
                    if let Some(label) = &public_label {
                        println!("Label:     {}", sanitize_public_label(label));
                    }
                    println!("(File names are encrypted in the payload)");
                }
            }
            BundleAction::List {
                in_file,
                password,
                password_file,
                json,
            } => {
                ensure_input_file(&in_file)?;
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let manifest = list_bundle(&in_file, pwd)?;

                if json {
                    let entries: Vec<serde_json::Value> = manifest
                        .entries
                        .iter()
                        .map(|e| {
                            serde_json::json!({
                                "path": e.relative_path,
                                "size": e.size,
                                "blake3": hex_encode(&e.blake3_hash),
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "file_count": manifest.entries.len(),
                            "entries": entries,
                        }))
                        .unwrap()
                    );
                } else {
                    println!("Bundle contents ({} files):", manifest.entries.len());
                    for entry in &manifest.entries {
                        println!("  {} ({} bytes)", entry.relative_path, entry.size);
                    }
                }
            }
            BundleAction::Diff {
                old_file,
                new_file,
                old_password,
                old_password_file,
                new_password,
                new_password_file,
                json,
            } => {
                ensure_input_file(&old_file)?;
                ensure_input_file(&new_file)?;

                let old_pwd = password_secret(old_password, old_password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing old password".into()))?;
                let new_pwd = password_secret(new_password, new_password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing new password".into()))?;

                let report = lvau_core::diff::diff_bundles(&old_file, old_pwd, &new_file, new_pwd)?;

                if json {
                    output::print_success("bundle-diff", &report)?;
                } else {
                    println!("Diff Report:");
                    println!("Old: {}", old_file.display());
                    println!("New: {}", new_file.display());
                    println!("--------------------------------------------------");
                    for diff in &report.files {
                        match diff.status {
                            lvau_core::diff::DiffStatus::Added => {
                                println!("+ {} ({} bytes)", diff.path, diff.new_size.unwrap_or(0));
                            }
                            lvau_core::diff::DiffStatus::Removed => {
                                println!("- {} ({} bytes)", diff.path, diff.old_size.unwrap_or(0));
                            }
                            lvau_core::diff::DiffStatus::Modified => {
                                println!(
                                    "~ {} ({} -> {} bytes)",
                                    diff.path,
                                    diff.old_size.unwrap_or(0),
                                    diff.new_size.unwrap_or(0)
                                );
                            }
                            lvau_core::diff::DiffStatus::Unchanged => {} // skip unchanged in non-JSON
                        }
                    }
                    println!("--------------------------------------------------");
                    println!(
                        "Summary: {} added, {} removed, {} modified, {} unchanged",
                        report.added_count,
                        report.removed_count,
                        report.modified_count,
                        report.unchanged_count
                    );
                }
            }
            BundleAction::Extract {
                in_file,
                out_dir,
                password,
                password_file,
                allow_symlinks,
                dry_run,
                force,
            } => {
                ensure_input_file(&in_file)?;
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;

                if !dry_run {
                    fs::create_dir_all(&out_dir)?;
                }

                let manifest =
                    extract_bundle(&in_file, &out_dir, pwd, allow_symlinks, force, dry_run)?;

                if dry_run {
                    println!(
                        "Dry run: would extract {} files to {}",
                        manifest.entries.len(),
                        out_dir.display()
                    );
                    for entry in &manifest.entries {
                        println!("  {} ({} bytes)", entry.relative_path, entry.size);
                    }
                } else {
                    println!(
                        "Extracted {} files to {}",
                        manifest.entries.len(),
                        out_dir.display()
                    );
                }
            }
            BundleAction::Verify {
                in_file,
                password,
                password_file,
            } => {
                ensure_input_file(&in_file)?;
                let pwd = password_secret(password, password_file.as_deref(), false)?
                    .ok_or_else(|| CliError::Message("Missing password".into()))?;
                let manifest = verify_bundle(&in_file, pwd)?;
                println!("Bundle verified: {} files", manifest.entries.len());
            }
        },
        Commands::Recipients { action } => match action {
            RecipientsAction::Group { action } => match action {
                GroupAction::Create { name } => {
                    let path = PathBuf::from(&name);
                    if path.exists() {
                        return Err(CliError::Message(format!(
                            "Group file already exists: {}",
                            name
                        )));
                    }
                    let group = lvau_core::groups::RecipientGroup {
                        name: name.clone(),
                        description: Some("Created by lvau-cli".into()),
                        recipients: Vec::new(),
                    };
                    group.save_to_file(&path).map_err(CliError::Message)?;
                    println!("Created empty recipient group at {}", name);
                }
                GroupAction::Add { name, pub_key } => {
                    let path = PathBuf::from(&name);
                    let mut group = lvau_core::groups::RecipientGroup::load_from_file(&path)
                        .map_err(CliError::Message)?;

                    let json = std::fs::read_to_string(&pub_key).map_err(|e| {
                        CliError::Message(format!("Failed to read public key file: {:?}", e))
                    })?;
                    let format: lvau_core::crypto::keys::HybridPublicKeyFormat =
                        serde_json::from_str(&json).map_err(|e| {
                            CliError::Message(format!("Invalid public key format: {:?}", e))
                        })?;

                    group.recipients.push(lvau_core::groups::GroupRecipient {
                        name: pub_key.file_stem().unwrap().to_string_lossy().to_string(),
                        key: format,
                    });

                    group.save_to_file(&path).map_err(CliError::Message)?;
                    println!("Added key {} to group {}", pub_key.display(), name);
                }
                GroupAction::Remove { name, fingerprint } => {
                    let path = PathBuf::from(&name);
                    let mut group = lvau_core::groups::RecipientGroup::load_from_file(&path)
                        .map_err(CliError::Message)?;

                    let initial_len = group.recipients.len();
                    group.recipients.retain(|r| r.name != fingerprint); // Simple match for now

                    if group.recipients.len() < initial_len {
                        group.save_to_file(&path).map_err(CliError::Message)?;
                        println!("Removed recipient {} from group {}", fingerprint, name);
                    } else {
                        println!("Recipient {} not found in group {}", fingerprint, name);
                    }
                }
                GroupAction::List { name } => {
                    let path = PathBuf::from(&name);
                    let group = lvau_core::groups::RecipientGroup::load_from_file(&path)
                        .map_err(CliError::Message)?;

                    println!("Group: {}", group.name);
                    println!("Recipients: {}", group.recipients.len());
                    for (i, rec) in group.recipients.iter().enumerate() {
                        println!("  [{}] {}", i + 1, rec.name);
                    }
                }
            },
        },
        Commands::Release { action } => match action {
            ReleaseAction::Attach {
                in_file,
                out_file,
                project_name,
                version,
                git_commit,
                build_timestamp,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_output_available(&out_file, force)?;

                lvau_core::release::attach_release_metadata(
                    &in_file,
                    &out_file,
                    project_name,
                    version,
                    git_commit,
                    build_timestamp,
                )
                .map_err(|e| {
                    CliError::Message(format!("Failed to attach release metadata: {e}"))
                })?;

                println!("Attached release metadata to {}", out_file.display());
            }
        },
        Commands::Recovery { action } => match action {
            RecoveryAction::Attach {
                in_file,
                out_file,
                data,
                force,
            } => {
                ensure_input_file(&in_file)?;
                ensure_output_available(&out_file, force)?;

                let bytes = data.into_bytes();
                lvau_core::release::attach_recovery_metadata(&in_file, &out_file, bytes).map_err(
                    |e| CliError::Message(format!("Failed to attach recovery metadata: {e}")),
                )?;

                println!("Attached recovery metadata to {}", out_file.display());
            }
            RecoveryAction::Split {
                in_file,
                shares,
                threshold,
                out_dir,
            } => {
                ensure_input_file(&in_file)?;
                if !out_dir.exists() {
                    fs::create_dir_all(&out_dir).map_err(CliError::Io)?;
                }

                let secret_data = fs::read(&in_file).map_err(CliError::Io)?;
                let generated_shares = split_secret(&secret_data, shares, threshold)
                    .map_err(|e| CliError::Message(format!("Failed to split secret: {:?}", e)))?;

                let file_stem = in_file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("secret");
                let share_outputs = generated_shares
                    .into_iter()
                    .map(|share| {
                        let path =
                            out_dir.join(format!("{}.{}.lvau-share", file_stem, share.index));
                        (share, path)
                    })
                    .collect::<Vec<_>>();

                for (_, share_path) in &share_outputs {
                    ensure_output_available(share_path, false)?;
                }
                for (share, share_path) in share_outputs {
                    share.to_file_with_force(&share_path, false).map_err(|e| {
                        CliError::Message(format!("Failed to write share: {:?}", e))
                    })?;
                    println!("Generated share: {}", share_path.display());
                }
                println!(
                    "Successfully generated {} shares (threshold: {}) in {}",
                    shares,
                    threshold,
                    out_dir.display()
                );
            }
            RecoveryAction::Combine {
                shares_dir,
                out_file,
                force,
            } => {
                ensure_output_available(&out_file, force)?;

                let mut loaded_shares = Vec::new();
                for entry in fs::read_dir(&shares_dir).map_err(CliError::Io)? {
                    let entry = entry.map_err(CliError::Io)?;
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("lvau-share") {
                        match RecoveryShare::from_file(&path) {
                            Ok(share) => loaded_shares.push(share),
                            Err(e) => eprintln!(
                                "Warning: Failed to load share {}: {:?}",
                                path.display(),
                                e
                            ),
                        }
                    }
                }

                if loaded_shares.is_empty() {
                    return Err(CliError::Message(
                        "No valid .lvau-share files found in directory".into(),
                    ));
                }

                let recovered = combine_shares(&loaded_shares)
                    .map_err(|e| CliError::Message(format!("Failed to combine shares: {:?}", e)))?;

                lvau_core::recovery::write_recovered_secret(&out_file, &recovered, force)?;
                println!("Successfully recovered secret to {}", out_file.display());
            }
            RecoveryAction::Inspect { in_file } => {
                ensure_input_file(&in_file)?;
                let share = RecoveryShare::from_file(&in_file)
                    .map_err(|e| CliError::Message(format!("Failed to read share: {:?}", e)))?;

                println!("Recovery Share:");
                println!("  Version:     {}", share.version);
                println!("  Index:       {}", share.index);
                println!("  Threshold:   {}", share.threshold);
                println!("  Fingerprint: {}", hex::encode(share.fingerprint));
                println!("  Data Length: {} bytes", share.share_data.len());
            }
        },
        Commands::Secret { action } => match action {
            SecretAction::Encrypt { in_file } => {
                ensure_input_file(&in_file)?;
                let out_file = in_file.with_extension(format!(
                    "{}.lvau",
                    in_file.extension().and_then(|e| e.to_str()).unwrap_or("")
                ));

                let pwd = SecretString::from(
                    rpassword::prompt_password("Enter password for secret: ")
                        .map_err(CliError::Io)?,
                );
                let confirm = SecretString::from(
                    rpassword::prompt_password("Confirm password: ").map_err(CliError::Io)?,
                );
                if pwd.expose_secret() != confirm.expose_secret() {
                    return Err(CliError::Message("Passwords do not match".into()));
                }

                let pol_path = Path::new(".lvau-policy.toml");
                let pol = if pol_path.exists() {
                    Some(
                        lvau_core::policy::CapsulePolicy::load_from_file(pol_path).map_err(
                            |e| CliError::Message(format!("Failed to load local policy: {}", e)),
                        )?,
                    )
                } else {
                    None
                };

                encrypt_file_password(
                    &in_file,
                    &out_file,
                    pwd,
                    None,
                    SecurityProfile::Balanced,
                    None,
                    pol.as_ref(),
                    false,
                )
                .map_err(|e| CliError::Message(format!("Crypto error: {:?}", e)))?;

                println!("Secret encrypted to {}", out_file.display());
            }
            SecretAction::Decrypt { in_file } => {
                ensure_input_file(&in_file)?;
                let out_file = in_file.with_extension("");
                ensure_output_available(&out_file, false)?;

                let pwd = SecretString::from(
                    rpassword::prompt_password("Enter password to decrypt: ")
                        .map_err(CliError::Io)?,
                );
                decrypt_file_password(&in_file, &out_file, pwd, None, None)
                    .map_err(|e| CliError::Message(format!("Crypto error: {:?}", e)))?;

                println!("Secret decrypted to {}", out_file.display());
            }
            SecretAction::Edit { in_file } => {
                ensure_input_file(&in_file)?;

                let pwd = SecretString::from(
                    rpassword::prompt_password("Enter password to edit: ").map_err(CliError::Io)?,
                );

                let dir = tempfile::tempdir().map_err(CliError::Io)?;
                let temp_file = dir.path().join(in_file.file_name().unwrap());

                decrypt_file_password(&in_file, &temp_file, pwd.clone(), None, None)
                    .map_err(|e| CliError::Message(format!("Crypto error: {:?}", e)))?;

                let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());

                let status = std::process::Command::new(&editor)
                    .arg(&temp_file)
                    .status()
                    .map_err(|e| {
                        CliError::Message(format!("Failed to launch editor {}: {}", editor, e))
                    })?;

                if !status.success() {
                    return Err(CliError::Message(
                        "Editor exited with non-zero status. Changes aborted.".into(),
                    ));
                }

                let pol_path = Path::new(".lvau-policy.toml");
                let pol = if pol_path.exists() {
                    Some(
                        lvau_core::policy::CapsulePolicy::load_from_file(pol_path).map_err(
                            |e| CliError::Message(format!("Failed to load local policy: {}", e)),
                        )?,
                    )
                } else {
                    None
                };

                encrypt_file_password_with_overwrite(
                    &temp_file,
                    &in_file,
                    pwd,
                    None,
                    SecurityProfile::Balanced,
                    None,
                    pol.as_ref(),
                    false,
                    true,
                )
                .map_err(|e| CliError::Message(format!("Crypto error: {:?}", e)))?;

                println!("Secret {} updated successfully.", in_file.display());
            }
            SecretAction::Print { in_file } => {
                ensure_input_file(&in_file)?;
                let pwd = SecretString::from(
                    rpassword::prompt_password("Enter password to print: ")
                        .map_err(CliError::Io)?,
                );

                let dir = tempfile::tempdir().map_err(CliError::Io)?;
                let temp_file = dir.path().join("print.tmp");

                decrypt_file_password(&in_file, &temp_file, pwd, None, None)
                    .map_err(|e| CliError::Message(format!("Crypto error: {:?}", e)))?;

                let content = fs::read_to_string(&temp_file).map_err(CliError::Io)?;
                println!("{}", content);
            }
        },
        Commands::SignKeygen { out_base, force } => {
            let sign_path = out_base.with_extension("lvau-sign");
            let verify_path = out_base.with_extension("lvau-verify");
            ensure_output_available(&sign_path, force)?;
            ensure_output_available(&verify_path, force)?;

            println!("Generating Ed25519 signing keypair...");
            let (signing_key, verify_key) = generate_signing_keypair();

            save_signing_key(&signing_key, &sign_path, force)?;
            save_verify_key(&verify_key, &verify_path, force)?;

            let fingerprint = key_fingerprint(&verify_key);
            println!("Signing key:  {}", sign_path.display());
            println!("Verify key:   {}", verify_path.display());
            println!("Fingerprint:  {}", hex_encode(&fingerprint));
        }
        Commands::Sign {
            in_file,
            signing_key,
            out_file,
            comment,
            force,
        } => {
            ensure_input_file(&in_file)?;
            ensure_input_file(&signing_key)?;
            ensure_output_available(&out_file, force)?;

            let key = load_signing_key(&signing_key)?;
            sign_file(&in_file, &out_file, &key, comment, force)?;

            println!("Signed: {}", out_file.display());
        }
        Commands::VerifySignature {
            in_file,
            verify_key,
        } => {
            ensure_input_file(&in_file)?;
            ensure_input_file(&verify_key)?;

            let key = load_verify_key(&verify_key)?;
            match verify_signature(&in_file, &key) {
                Ok(fingerprint) => {
                    println!("Signature valid.");
                    println!("Signer fingerprint: {}", hex_encode(&fingerprint));
                }
                Err(lvau_core::signing::SigningError::NotSigned) => {
                    println!("File is not signed.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Signature verification failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Approve {
            in_file,
            out_file,
            signing_key,
            comment,
            force,
        } => {
            ensure_input_file(&in_file)?;
            ensure_input_file(&signing_key)?;
            ensure_output_available(&out_file, force)?;

            let key = load_signing_key(&signing_key)?;
            lvau_core::signing::add_approval_seal(&in_file, &out_file, &key, comment, force)?;

            println!("Approval seal added: {}", out_file.display());
        }
        Commands::Approvals {
            in_file,
            verify_key,
        } => {
            ensure_input_file(&in_file)?;
            ensure_input_file(&verify_key)?;

            let key = load_verify_key(&verify_key)?;
            match lvau_core::signing::verify_approvals(&in_file, &key) {
                Ok(true) => {
                    println!("Valid approval seal found from this key.");
                }
                Ok(false) => {
                    println!("No valid approval seal found from this key.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error checking approvals: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Doctor => {
            println!("Lvau Diagnostics");
            println!("----------------");
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            println!("OS: {}", std::env::consts::OS);
            println!("Arch: {}", std::env::consts::ARCH);

            let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("unknown"));
            println!("Executable path: {}", exe_path.display());

            let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
            let stub_name = if cfg!(windows) {
                "lvau-stub.exe"
            } else {
                "lvau-stub"
            };
            let stub_path = exe_dir.join(stub_name);
            println!("SFX Stub available: {}", stub_path.exists());

            let test_file = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".lvau-write-test");
            let writable = fs::write(&test_file, b"test").is_ok();
            if writable {
                let _ = fs::remove_file(&test_file);
            }
            println!("Current directory writable: {}", writable);
        }
        Commands::SelfTest => {
            println!("Running self-test...");
            run_self_test()?;
        }
    }
    Ok(())
}

fn run_self_test() -> Result<(), CliError> {
    let mut passed = 0;
    let mut failed = 0;

    let mut run_test = |name: &str, test: Box<dyn Fn() -> Result<(), CliError>>| {
        print!("Test {:<30} ... ", name);
        let _ = io::stdout().flush();
        match test() {
            Ok(_) => {
                println!("OK");
                passed += 1;
            }
            Err(e) => {
                println!("FAILED ({})", e);
                failed += 1;
            }
        }
    };

    run_test(
        "password_roundtrip",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_pw.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_pw.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_pw.bin");
            let data = b"hello world password test";
            fs::write(&in_path, data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                SecretString::from("testpass".to_string()),
                None,
                SecurityProfile::Fast,
                None,
                None,
                false,
            )?;
            decrypt_file_password(
                &enc_path,
                &dec_path,
                SecretString::from("testpass".to_string()),
                None,
                None,
            )?;

            let dec_data = fs::read(&dec_path)?;
            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if dec_data == data {
                Ok(())
            } else {
                Err(CliError::Message("Data mismatch".into()))
            }
        }),
    );

    run_test(
        "wrong_password_rejection",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_wp.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_wp.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_wp.bin");
            let data = b"hello world password test";
            fs::write(&in_path, data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                SecretString::from("testpass".to_string()),
                None,
                SecurityProfile::Fast,
                None,
                None,
                false,
            )?;
            let res = decrypt_file_password(
                &enc_path,
                &dec_path,
                SecretString::from("wrongpass".to_string()),
                None,
                None,
            );

            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if res.is_err() {
                Ok(())
            } else {
                Err(CliError::Message("Expected decryption to fail".into()))
            }
        }),
    );

    run_test(
        "tamper_detection",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_t.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_t.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_t.bin");
            let data = b"hello world password test";
            fs::write(&in_path, data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                SecretString::from("testpass".to_string()),
                None,
                SecurityProfile::Fast,
                None,
                None,
                false,
            )?;

            let mut enc_data = fs::read(&enc_path)?;
            let len = enc_data.len();
            if len > 0 {
                enc_data[len - 1] ^= 1; // flip a bit in ciphertext
            }
            fs::write(&enc_path, enc_data)?;

            let res = decrypt_file_password(
                &enc_path,
                &dec_path,
                SecretString::from("testpass".to_string()),
                None,
                None,
            );

            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if res.is_err() {
                Ok(())
            } else {
                Err(CliError::Message(
                    "Expected tamper detection to fail".into(),
                ))
            }
        }),
    );

    run_test(
        "streaming_large_file",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_lf.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_lf.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_lf.bin");
            let data = vec![0x42u8; 2_500_000]; // 2.5 MB to force multi-chunk
            fs::write(&in_path, &data)?;

            encrypt_file_password(
                &in_path,
                &enc_path,
                SecretString::from("testpass".to_string()),
                None,
                SecurityProfile::Fast,
                None,
                None,
                false,
            )?;
            decrypt_file_password(
                &enc_path,
                &dec_path,
                SecretString::from("testpass".to_string()),
                None,
                None,
            )?;

            let dec_data = fs::read(&dec_path)?;
            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if dec_data == data {
                Ok(())
            } else {
                Err(CliError::Message("Data mismatch on large file".into()))
            }
        }),
    );

    run_test(
        "keypair_roundtrip",
        Box::new(|| {
            let in_path = std::env::temp_dir().join("lvau_test_in_kp.bin");
            let enc_path = std::env::temp_dir().join("lvau_test_enc_kp.lvau");
            let dec_path = std::env::temp_dir().join("lvau_test_dec_kp.bin");
            let data = b"hello world keypair test";
            fs::write(&in_path, data)?;

            let (priv_key, pub_key) = generate_keypair();

            let pubs = vec![pub_key];
            encrypt_file_keypairs(
                &in_path,
                &enc_path,
                &pubs,
                SecurityProfile::Fast,
                None,
                None,
                false,
            )?;
            decrypt_file_keypair(&enc_path, &dec_path, &priv_key, None)?;

            let dec_data = fs::read(&dec_path)?;
            let _ = fs::remove_file(&in_path);
            let _ = fs::remove_file(&enc_path);
            let _ = fs::remove_file(&dec_path);

            if dec_data == data {
                Ok(())
            } else {
                Err(CliError::Message("Data mismatch".into()))
            }
        }),
    );

    println!("\nSelf-test summary: {} passed, {} failed", passed, failed);
    if failed > 0 {
        Err(CliError::Message("One or more self-tests failed".into()))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn run_with_platform_stack() -> Result<(), CliError> {
    const WINDOWS_STACK_SIZE: usize = 8 * 1024 * 1024;

    let worker = std::thread::Builder::new()
        .name("lvau-cli".to_string())
        .stack_size(WINDOWS_STACK_SIZE)
        .spawn(run)
        .map_err(|error| CliError::Message(format!("Failed to start CLI worker: {error}")))?;

    worker
        .join()
        .unwrap_or_else(|_| Err(CliError::Message("CLI worker thread panicked".into())))
}

#[cfg(not(windows))]
fn run_with_platform_stack() -> Result<(), CliError> {
    run()
}

fn main() {
    if let Err(error) = run_with_platform_stack() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        copy_exact_len, read_secret_file, sanitize_public_label, sfx_payload_temp_dir,
        MAX_SECRET_FILE_SIZE,
    };
    use std::io::Cursor;

    #[test]
    fn sfx_payload_uses_a_private_random_directory() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("app.exe");
        let predictable = output.with_extension("tmp.lvau");
        std::fs::write(&predictable, b"keep").unwrap();

        let temporary = sfx_payload_temp_dir(&output).unwrap();
        let payload = temporary.path().join("payload.lvau");

        assert!(payload.starts_with(temporary.path()));
        assert!(!payload.exists());
        assert_eq!(std::fs::read(predictable).unwrap(), b"keep");
    }

    #[test]
    fn sfx_payload_copy_rejects_length_changes() {
        let mut source = Cursor::new(vec![0x5au8; 3]);
        let mut output = Vec::new();
        let error = copy_exact_len(&mut source, &mut output, 4, "SFX payload").unwrap_err();
        assert!(error.to_string().contains("changed while being copied"));
        assert_eq!(output.len(), 3);
    }

    #[test]
    fn oversized_secret_file_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-secret.txt");
        std::fs::write(&path, vec![b'x'; MAX_SECRET_FILE_SIZE as usize + 1]).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = read_secret_file(&path).unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    #[cfg(unix)]
    fn password_file_must_not_be_group_or_world_accessible() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        fs::write(&path, "secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = read_secret_file(&path).unwrap_err();
        assert!(error.to_string().contains("permissions"));
    }

    #[test]
    fn public_label_display_neutralizes_control_characters() {
        assert_eq!(sanitize_public_label("ok-label_123"), "ok-label_123");
        let injected = "x\x1b[2J\x1b]0;pwned\x07\ny";
        let sanitized = sanitize_public_label(injected);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains('\u{FFFD}'));
        let long = "a".repeat(600);
        assert!(sanitize_public_label(&long).ends_with("…[truncated]"));
    }
}

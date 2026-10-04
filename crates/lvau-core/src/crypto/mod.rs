pub mod framing;
pub mod key_schedule;
pub mod keys;
pub mod lco;
pub mod output;
pub mod parallel;
pub mod password;
pub mod suite;

use parallel::{stream_decrypt_payload, stream_encrypt_payload};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use keys::{HybridPrivateKey, HybridPublicKey};
use ml_kem::{Decapsulate, Encapsulate};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use log::{debug, info};
use lvau_protocol::envelope::{
    AlgorithmId, ContentType, Envelope, EnvelopeHeader, KdfParams, Recipient, SecurityProfile,
    CURRENT_VERSION, LEGACY_VERSION, MAGIC_REAL,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Envelope validation failed: {0}")]
    Validation(&'static str),
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed (tampered data or wrong key)")]
    DecryptionFailed,
    #[error("Unsupported security profile")]
    UnsupportedProfile,
    #[error("Missing KDF parameters")]
    MissingKdfParams,
    #[error("Missing secondary nonce for cascade")]
    MissingSecondaryNonce,
    #[error("Refusing to overwrite existing output file")]
    OutputExists,
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}

pub enum EncryptCredential {
    Password(SecretString, Option<SecretString>),
    Keypairs(Vec<crate::crypto::keys::HybridPublicKey>),
}

fn derive_master_key(
    password: &SecretString,
    seed: Option<&SecretString>,
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    match kdf {
        KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
            salt,
        } => {
            info!(
                "Initializing Argon2id KDF with m_cost={}, t_cost={}, p_cost={}",
                m_cost, t_cost, p_cost
            );
            let params = Params::new(*m_cost, *t_cost, *p_cost, Some(32))
                .map_err(|_| CryptoError::UnsupportedProfile)?;

            let argon2 = if let Some(s) = seed {
                debug!("Applying cryptographic seed (pepper) to KDF.");
                Argon2::new_with_secret(
                    s.expose_secret().as_bytes(),
                    Algorithm::Argon2id,
                    Version::V0x13,
                    params,
                )
                .map_err(|_| CryptoError::EncryptionFailed)?
            } else {
                Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            };

            let mut master_key = Zeroizing::new([0u8; 32]);
            info!("Deriving master key from password...");
            argon2
                .hash_password_into(password.expose_secret().as_bytes(), salt, &mut *master_key)
                .map_err(|_| CryptoError::DecryptionFailed)?;

            Ok(master_key)
        }
    }
}

const PAYLOAD_AAD_V2_DOMAIN: &[u8] = b"Lvau payload AAD v2\0";
pub const MAX_ENVELOPE_SIZE: usize = 1024 * 1024;
const MAX_RECIPIENTS: usize = 64;

#[derive(Serialize)]
struct PayloadAadV2<'a> {
    header: &'a EnvelopeHeader,
    plaintext_len: u64,
    nonce: &'a [u8; 24],
    secondary_nonce: &'a Option<[u8; 12]>,
    metadata: &'a [u8],
    content_type: &'a Option<ContentType>,
    public_label: &'a Option<String>,
    policy_overridden: bool,
}

#[derive(Deserialize)]
struct LegacyEnvelopeV1 {
    header: EnvelopeHeader,
    plaintext_len: u64,
    nonce: [u8; 24],
    secondary_nonce: Option<[u8; 12]>,
    aad_hash: [u8; 32],
    metadata: Vec<u8>,
}

impl From<LegacyEnvelopeV1> for Envelope {
    fn from(legacy: LegacyEnvelopeV1) -> Self {
        Self {
            header: legacy.header,
            plaintext_len: legacy.plaintext_len,
            nonce: legacy.nonce,
            secondary_nonce: legacy.secondary_nonce,
            aad_hash: legacy.aad_hash,
            metadata: legacy.metadata,
            content_type: None,
            signature: None,
            public_label: None,
            approvals: Vec::new(),
            release_metadata: None,
            policy_overridden: false,
            recovery_metadata: None,
        }
    }
}

fn compute_aad_hash(envelope: &Envelope) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Sha256::new();
    match envelope.header.version {
        LEGACY_VERSION => {
            hasher.update(postcard::to_allocvec(&envelope.header)?);
        }
        CURRENT_VERSION => {
            hasher.update(PAYLOAD_AAD_V2_DOMAIN);
            hasher.update(postcard::to_allocvec(&PayloadAadV2 {
                header: &envelope.header,
                plaintext_len: envelope.plaintext_len,
                nonce: &envelope.nonce,
                secondary_nonce: &envelope.secondary_nonce,
                metadata: &envelope.metadata,
                content_type: &envelope.content_type,
                public_label: &envelope.public_label,
                policy_overridden: envelope.policy_overridden,
            })?);
        }
        _ => return Err(CryptoError::Validation("Unsupported format version")),
    }
    Ok(hasher.finalize().into())
}

fn expected_argon2_costs(profile: &SecurityProfile) -> (u32, u32, u32) {
    match profile {
        SecurityProfile::Fast => (16_384, 1, 1),
        SecurityProfile::Balanced => (65_536, 2, 1),
        SecurityProfile::Archive => (262_144, 3, 2),
        SecurityProfile::Paranoid | SecurityProfile::Extreme => (1_048_576, 4, 4),
    }
}

fn validate_envelope_resources(envelope: &Envelope) -> Result<(), CryptoError> {
    if envelope.header.recipients.is_empty() {
        return Err(CryptoError::Validation("Envelope has no recipients"));
    }
    if envelope.header.recipients.len() > MAX_RECIPIENTS {
        return Err(CryptoError::Validation("Envelope has too many recipients"));
    }

    if !matches!(
        envelope.header.algorithm,
        AlgorithmId::XChaCha20Poly1305
            | AlgorithmId::CascadeAesGcmXChaCha
            | AlgorithmId::TripleCascadeAesXChaChaLco
    ) {
        return Err(CryptoError::Validation(
            "Unsupported payload encryption algorithm",
        ));
    }

    let password_recipients = envelope
        .header
        .recipients
        .iter()
        .filter(|recipient| matches!(recipient, Recipient::Password { .. }))
        .count();
    let hybrid_recipients = envelope.header.recipients.len() - password_recipients;
    if password_recipients != 0 && hybrid_recipients != 0 {
        return Err(CryptoError::Validation(
            "Mixed password and key-pair recipients are unsupported",
        ));
    }

    for recipient in &envelope.header.recipients {
        let wrapped_key_len = match recipient {
            Recipient::Password {
                encrypted_file_key, ..
            }
            | Recipient::X25519MlkemHybrid {
                encrypted_file_key, ..
            } => encrypted_file_key.len(),
        };
        if wrapped_key_len != 48 {
            return Err(CryptoError::Validation("Invalid wrapped file-key length"));
        }
    }

    if password_recipients > 0 {
        let Some(KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
            ..
        }) = envelope.header.kdf.as_ref()
        else {
            return Err(CryptoError::Validation(
                "Password recipient is missing Argon2id parameters",
            ));
        };
        if (*m_cost, *t_cost, *p_cost) != expected_argon2_costs(&envelope.header.profile) {
            return Err(CryptoError::Validation(
                "Argon2id parameters do not match the security profile",
            ));
        }
    } else if envelope.header.kdf.is_some() {
        return Err(CryptoError::Validation(
            "Key-pair envelope must not include password KDF parameters",
        ));
    }

    let needs_secondary_nonce = matches!(
        envelope.header.algorithm,
        AlgorithmId::CascadeAesGcmXChaCha | AlgorithmId::TripleCascadeAesXChaChaLco
    );
    if needs_secondary_nonce != envelope.secondary_nonce.is_some() {
        return Err(CryptoError::Validation(
            "Secondary nonce does not match the payload algorithm",
        ));
    }

    Ok(())
}

pub fn verify_aad_hash(envelope: &Envelope) -> Result<(), CryptoError> {
    let computed_hash = compute_aad_hash(envelope)?;
    if computed_hash != envelope.aad_hash {
        return Err(CryptoError::Validation(
            "Envelope header authentication data mismatch",
        ));
    }
    Ok(())
}

fn wrap_key_xchacha(
    key_to_wrap: &[u8],
    wrapping_key: &[u8; 32],
    nonce_bytes: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: key_to_wrap,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

fn unwrap_key_xchacha(
    wrapped_key: &[u8],
    wrapping_key: &[u8; 32],
    nonce_bytes: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(wrapping_key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: wrapped_key,
                aad: &[],
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn write_envelope_and_payload(
    output_path: &Path,
    envelope: &Envelope,
    algorithm: &AlgorithmId,
    hk: &Hkdf<Sha256>,
    reader: &mut dyn Read,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let encoded_envelope = postcard::to_allocvec(envelope)?;
    if encoded_envelope.is_empty() || encoded_envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(CryptoError::Validation("Envelope size is invalid"));
    }
    let env_len = u32::try_from(encoded_envelope.len())
        .map_err(|_| CryptoError::Validation("Envelope size is invalid"))?;

    let mut temp_file = NamedTempFile::new_in(parent)?;
    temp_file.write_all(&env_len.to_le_bytes())?;
    temp_file.write_all(&encoded_envelope)?;

    let plaintext_len = stream_encrypt_payload(
        algorithm,
        envelope.header.version,
        reader,
        &mut temp_file,
        hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        progress_callback,
    )?;
    if plaintext_len != envelope.plaintext_len {
        return Err(CryptoError::Validation(
            "Input length changed during encryption",
        ));
    }

    temp_file.as_file().sync_all()?;
    output::persist_temp_path(temp_file.into_temp_path(), output_path, replace_existing).map_err(
        |error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => CryptoError::OutputExists,
            _ => CryptoError::Io(error),
        },
    )
}

fn decode_postcard_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, postcard::Error> {
    let (value, remaining) = postcard::take_from_bytes(bytes)?;
    if remaining.is_empty() {
        Ok(value)
    } else {
        Err(postcard::Error::DeserializeBadEncoding)
    }
}

pub fn decode_envelope_bytes(bytes: &[u8]) -> Result<Envelope, CryptoError> {
    let envelope = match decode_postcard_exact::<Envelope>(bytes) {
        Ok(envelope) => envelope,
        Err(current_error) => match decode_postcard_exact::<LegacyEnvelopeV1>(bytes) {
            Ok(legacy) => legacy.into(),
            Err(_) => return Err(CryptoError::Serialization(current_error)),
        },
    };

    envelope.validate().map_err(CryptoError::Validation)?;
    validate_envelope_resources(&envelope)?;
    verify_aad_hash(&envelope)?;
    Ok(envelope)
}

fn read_envelope(reader: &mut dyn Read) -> Result<Envelope, CryptoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let env_len = u32::from_le_bytes(len_buf) as usize;
    if env_len == 0 {
        return Err(CryptoError::Validation("Envelope is empty"));
    }
    if env_len > MAX_ENVELOPE_SIZE {
        return Err(CryptoError::Validation("Envelope too large"));
    }

    let mut env_bytes = vec![0u8; env_len];
    reader.read_exact(&mut env_bytes)?;

    decode_envelope_bytes(&env_bytes)
}

pub fn read_envelope_from_path(input_path: &Path) -> Result<Envelope, CryptoError> {
    let mut reader = File::open(input_path)?;
    read_envelope(&mut reader)
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    seed: Option<SecretString>,
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
) -> Result<(), CryptoError> {
    encrypt_file_password_with_overwrite(
        input_path,
        output_path,
        password,
        seed,
        profile,
        progress_callback,
        policy,
        allow_policy_override,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_file_password_with_overwrite(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    seed: Option<SecretString>,
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    encrypt_file_password_with_content_type_with_overwrite(
        input_path,
        output_path,
        password,
        seed,
        profile,
        progress_callback,
        policy,
        allow_policy_override,
        None,
        replace_existing,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_file_password_with_content_type_with_overwrite(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    seed: Option<SecretString>,
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
    content_type: Option<ContentType>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    if password.expose_secret().is_empty() {
        return Err(CryptoError::Validation("Password must not be empty"));
    }
    if seed
        .as_ref()
        .is_some_and(|value| value.expose_secret().is_empty())
    {
        return Err(CryptoError::Validation("Seed must not be empty"));
    }

    info!("Starting encryption of {}", input_path.display());
    let mut rng = OsRng;

    let mut reader = File::open(input_path)?;
    let plaintext_len = reader.metadata()?.len();

    let (m_cost, t_cost, p_cost) = match profile {
        SecurityProfile::Fast => (16384, 1, 1),
        SecurityProfile::Balanced => (65536, 2, 1),
        SecurityProfile::Archive => (262144, 3, 2),
        SecurityProfile::Paranoid => (1048576, 4, 4),
        SecurityProfile::Extreme => (1048576, 4, 4),
    };

    let algorithm = match profile {
        SecurityProfile::Extreme => AlgorithmId::TripleCascadeAesXChaChaLco,
        SecurityProfile::Paranoid => AlgorithmId::CascadeAesGcmXChaCha,
        _ => AlgorithmId::XChaCha20Poly1305,
    };
    info!("Selected algorithm: {:?}", algorithm);

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let kdf = KdfParams::Argon2id {
        m_cost,
        t_cost,
        p_cost,
        salt,
    };
    let master_key = derive_master_key(&password, seed.as_ref(), &kdf)?;

    // Derive Key Wrapping Key
    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    key_schedule::derive_subkey(&kw_hk, key_schedule::KeyPurpose::KeyWrap, &mut kwk)?;

    // Generate FEK (File Encryption Key)
    let mut fek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *fek);

    let mut wrap_nonce = [0u8; 24];
    rng.fill_bytes(&mut wrap_nonce);
    let encrypted_file_key = wrap_key_xchacha(&*fek, &kwk, &wrap_nonce)?;

    let mut nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut nonce_bytes);

    let mut secondary_nonce_bytes = None;
    if algorithm == AlgorithmId::CascadeAesGcmXChaCha
        || algorithm == AlgorithmId::TripleCascadeAesXChaChaLco
    {
        let mut sn = [0u8; 12];
        rng.fill_bytes(&mut sn);
        secondary_nonce_bytes = Some(sn);
    }

    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: CURRENT_VERSION,
        profile,
        algorithm: algorithm.clone(),
        kdf: Some(kdf),
        recipients: vec![Recipient::Password {
            nonce: wrap_nonce,
            encrypted_file_key,
        }],
    };

    let mut envelope = Envelope {
        header,
        plaintext_len,
        nonce: nonce_bytes,
        secondary_nonce: secondary_nonce_bytes,
        aad_hash: [0; 32],
        metadata: Vec::new(),
        content_type,
        signature: None,
        public_label: None,
        approvals: Vec::new(),
        release_metadata: None,
        policy_overridden: allow_policy_override,
        recovery_metadata: None,
    };
    envelope.aad_hash = compute_aad_hash(&envelope)?;
    validate_envelope_resources(&envelope)?;

    if let Some(pol) = policy {
        let result = crate::policy::lint_envelope(&envelope, pol);
        if !result.is_valid() && !allow_policy_override {
            let msg = result
                .violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CryptoError::PolicyViolation(msg));
        }
    }

    let hk = Hkdf::<Sha256>::new(None, &*fek);

    info!(
        "Writing encrypted envelope and streaming to {}",
        output_path.display()
    );
    write_envelope_and_payload(
        output_path,
        &envelope,
        &algorithm,
        &hk,
        &mut reader,
        progress_callback,
        replace_existing,
    )?;

    Ok(())
}

fn derive_contributory_x25519(
    secret: &StaticSecret,
    public: &X25519PublicKey,
) -> Result<x25519_dalek::SharedSecret, CryptoError> {
    // Zero is explicitly non-contributory. The post-DH check also rejects the other
    // low-order inputs that collapse the classical contribution of the hybrid suite.
    if public.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CryptoError::Validation(
            "Recipient X25519 public key is non-contributory",
        ));
    }
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(CryptoError::Validation(
            "Recipient X25519 public key is non-contributory",
        ));
    }
    Ok(shared)
}

pub fn encrypt_file_keypairs(
    in_path: &Path,
    out_path: &Path,
    recipient_pubs: &[HybridPublicKey],
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
) -> Result<(), CryptoError> {
    encrypt_file_keypairs_with_overwrite(
        in_path,
        out_path,
        recipient_pubs,
        profile,
        progress_callback,
        policy,
        allow_policy_override,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_file_keypairs_with_overwrite(
    in_path: &Path,
    out_path: &Path,
    recipient_pubs: &[HybridPublicKey],
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    encrypt_file_keypairs_with_content_type_with_overwrite(
        in_path,
        out_path,
        recipient_pubs,
        profile,
        progress_callback,
        policy,
        allow_policy_override,
        None,
        replace_existing,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_file_keypairs_with_content_type_with_overwrite(
    in_path: &Path,
    out_path: &Path,
    recipient_pubs: &[HybridPublicKey],
    profile: SecurityProfile,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
    content_type: Option<ContentType>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    info!(
        "Starting hybrid keypair encryption for {}",
        in_path.display()
    );

    let mut reader = File::open(in_path)?;
    let plaintext_len = reader.metadata()?.len();
    let mut rng = OsRng;

    let algorithm = match profile {
        SecurityProfile::Extreme => AlgorithmId::TripleCascadeAesXChaChaLco,
        SecurityProfile::Paranoid => AlgorithmId::CascadeAesGcmXChaCha,
        _ => AlgorithmId::XChaCha20Poly1305,
    };

    let mut nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut nonce_bytes);

    let mut secondary_nonce_bytes = None;
    if algorithm == AlgorithmId::CascadeAesGcmXChaCha
        || algorithm == AlgorithmId::TripleCascadeAesXChaChaLco
    {
        let mut sn = [0u8; 12];
        rng.fill_bytes(&mut sn);
        secondary_nonce_bytes = Some(sn);
    }

    let mut fek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *fek);

    let mut envelope_recipients = Vec::new();

    for pubkey in recipient_pubs {
        let ephem_x25519_priv = StaticSecret::random();
        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);
        let x25519_ss = derive_contributory_x25519(&ephem_x25519_priv, &pubkey.x25519)?;

        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();

        let mut combined_ss = Zeroizing::new(Vec::new());
        combined_ss.extend_from_slice(x25519_ss.as_bytes());
        combined_ss.extend_from_slice(mlkem_ss.as_slice());

        let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);
        let mut kwk = Zeroizing::new([0u8; 32]);
        kw_hk
            .expand(b"Lvau-Hybrid-Wrap", &mut *kwk)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let wrap_nonce = [0u8; 24];
        let encrypted_file_key = wrap_key_xchacha(&*fek, &kwk, &wrap_nonce)?;

        envelope_recipients.push(Recipient::X25519MlkemHybrid {
            ephemeral_public_x25519: ephem_x25519_pub.to_bytes(),
            mlkem_ciphertext: mlkem_ct.as_slice().to_vec(),
            encrypted_file_key,
        });
    }

    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: CURRENT_VERSION,
        profile: profile.clone(),
        algorithm: algorithm.clone(),
        kdf: None,
        recipients: envelope_recipients,
    };

    let mut envelope = Envelope {
        header,
        plaintext_len,
        nonce: nonce_bytes,
        secondary_nonce: secondary_nonce_bytes,
        aad_hash: [0; 32],
        metadata: vec![],
        content_type,
        signature: None,
        public_label: None,
        approvals: Vec::new(),
        release_metadata: None,
        policy_overridden: allow_policy_override,
        recovery_metadata: None,
    };
    envelope.aad_hash = compute_aad_hash(&envelope)?;
    validate_envelope_resources(&envelope)?;

    if let Some(pol) = policy {
        let result = crate::policy::lint_envelope(&envelope, pol);
        if !result.is_valid() && !allow_policy_override {
            let msg = result
                .violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CryptoError::PolicyViolation(msg));
        }
    }

    let hk = Hkdf::<Sha256>::new(None, &*fek);
    write_envelope_and_payload(
        out_path,
        &envelope,
        &algorithm,
        &hk,
        &mut reader,
        progress_callback,
        replace_existing,
    )?;
    Ok(())
}

fn unwrap_keypair_file_key(
    envelope: &Envelope,
    priv_key: &HybridPrivateKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    for recipient in &envelope.header.recipients {
        let Recipient::X25519MlkemHybrid {
            ephemeral_public_x25519,
            mlkem_ciphertext,
            encrypted_file_key,
        } = recipient
        else {
            continue;
        };

        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);
        let x25519_ss = match derive_contributory_x25519(&priv_key.x25519, &ephem_pub) {
            Ok(shared) => shared,
            Err(_) => continue,
        };
        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {
            Ok(ciphertext) => ciphertext,
            Err(_) => continue,
        };
        let mlkem_ss = priv_key.mlkem.decapsulate(&mlkem_ct);

        let mut combined_ss = Zeroizing::new(Vec::new());
        combined_ss.extend_from_slice(x25519_ss.as_bytes());
        combined_ss.extend_from_slice(mlkem_ss.as_slice());

        let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);
        let mut kwk = Zeroizing::new([0u8; 32]);
        if kw_hk.expand(b"Lvau-Hybrid-Wrap", &mut *kwk).is_err() {
            continue;
        }

        let wrap_nonce = [0u8; 24];
        if let Ok(key) = unwrap_key_xchacha(encrypted_file_key, &kwk, &wrap_nonce) {
            return Ok(Zeroizing::new(key));
        }
    }

    Err(CryptoError::DecryptionFailed)
}

fn write_decrypted_payload_atomic(
    output_path: &Path,
    envelope: &Envelope,
    algorithm: &AlgorithmId,
    hk: &Hkdf<Sha256>,
    reader: &mut dyn Read,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent)?;
    stream_decrypt_payload(
        algorithm,
        envelope.header.version,
        reader,
        &mut temp_file,
        hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        progress_callback,
    )?;
    temp_file.as_file().sync_all()?;
    output::persist_temp_path(temp_file.into_temp_path(), output_path, replace_existing).map_err(
        |error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => CryptoError::OutputExists,
            _ => CryptoError::Io(error),
        },
    )
}

pub fn decrypt_file_keypair(
    in_path: &Path,
    out_path: &Path,
    priv_key: &HybridPrivateKey,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    decrypt_file_keypair_with_overwrite(in_path, out_path, priv_key, progress_callback, false)
}

pub fn decrypt_file_keypair_with_overwrite(
    in_path: &Path,
    out_path: &Path,
    priv_key: &HybridPrivateKey,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut reader = File::open(in_path)?;
    let envelope = read_envelope(&mut reader)?;

    let fek = unwrap_keypair_file_key(&envelope, priv_key)?;
    let hk = Hkdf::<Sha256>::new(None, &fek);
    write_decrypted_payload_atomic(
        out_path,
        &envelope,
        &envelope.header.algorithm,
        &hk,
        &mut reader,
        progress_callback,
        replace_existing,
    )?;

    Ok(())
}

pub fn decrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    seed: Option<SecretString>,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    decrypt_file_password_with_overwrite(
        input_path,
        output_path,
        password,
        seed,
        progress_callback,
        false,
    )
}

pub fn decrypt_file_password_with_overwrite(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    seed: Option<SecretString>,
    progress_callback: Option<&mut dyn FnMut(u64)>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    info!("Starting decryption of {}", input_path.display());
    let mut reader = File::open(input_path)?;
    let envelope = read_envelope(&mut reader)?;

    let kdf = envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::MissingKdfParams)?;

    let master_key = derive_master_key(&password, seed.as_ref(), kdf)?;

    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Key-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::Password { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;

    let fek = if let Recipient::Password {
        nonce,
        encrypted_file_key,
    } = recipient
    {
        unwrap_key_xchacha(encrypted_file_key, &kwk, nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };

    let hk = Hkdf::<Sha256>::new(None, &fek);

    info!("Streaming decrypted file to {}", output_path.display());
    write_decrypted_payload_atomic(
        output_path,
        &envelope,
        &envelope.header.algorithm,
        &hk,
        &mut reader,
        progress_callback,
        replace_existing,
    )?;

    Ok(())
}

pub fn verify_file_keypair(
    in_path: &Path,
    priv_key: &HybridPrivateKey,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    info!("Starting verification of {}", in_path.display());
    let mut reader = File::open(in_path)?;
    let envelope = read_envelope(&mut reader)?;

    let fek = unwrap_keypair_file_key(&envelope, priv_key)?;
    let hk = Hkdf::<Sha256>::new(None, &fek);

    info!("Verifying payload integrity without writing to disk");
    let mut sink = std::io::sink();
    stream_decrypt_payload(
        &envelope.header.algorithm,
        envelope.header.version,
        &mut reader,
        &mut sink,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        progress_callback,
    )?;

    Ok(())
}

pub fn verify_file_password(
    input_path: &Path,
    password: SecretString,
    seed: Option<SecretString>,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    info!("Starting verification of {}", input_path.display());
    let mut reader = File::open(input_path)?;
    let envelope = read_envelope(&mut reader)?;

    let kdf = envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::MissingKdfParams)?;

    let master_key = derive_master_key(&password, seed.as_ref(), kdf)?;

    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Key-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::Password { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;

    let fek = if let Recipient::Password {
        nonce,
        encrypted_file_key,
    } = recipient
    {
        unwrap_key_xchacha(encrypted_file_key, &kwk, nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };

    let hk = Hkdf::<Sha256>::new(None, &fek);

    info!("Verifying payload integrity without writing to disk");
    let mut sink = std::io::sink();
    stream_decrypt_payload(
        &envelope.header.algorithm,
        envelope.header.version,
        &mut reader,
        &mut sink,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        progress_callback,
    )?;

    Ok(())
}

pub fn inspect_envelope(input_path: &Path) -> Result<EnvelopeHeader, CryptoError> {
    let mut reader = File::open(input_path)?;
    let envelope = read_envelope(&mut reader)?;
    Ok(envelope.header)
}

// Stubs for backward compatibility used by stub crate
pub fn decrypt_memory_password(
    encoded_envelope: &[u8],
    password: SecretString,
    seed: Option<SecretString>,
) -> Result<Vec<u8>, CryptoError> {
    let mut cursor = std::io::Cursor::new(encoded_envelope);
    let envelope = read_envelope(&mut cursor)?;
    let kdf = envelope
        .header
        .kdf
        .as_ref()
        .ok_or(CryptoError::MissingKdfParams)?;
    let master_key = derive_master_key(&password, seed.as_ref(), kdf)?;
    let kw_hk = Hkdf::<Sha256>::new(None, &*master_key);
    let mut kwk = Zeroizing::new([0u8; 32]);
    kw_hk
        .expand(b"Lvau-Key-Wrap", &mut *kwk)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let recipient = envelope
        .header
        .recipients
        .iter()
        .find(|r| matches!(r, Recipient::Password { .. }))
        .ok_or(CryptoError::DecryptionFailed)?;
    let fek = if let Recipient::Password {
        nonce,
        encrypted_file_key,
    } = recipient
    {
        unwrap_key_xchacha(encrypted_file_key, &kwk, nonce)?
    } else {
        return Err(CryptoError::DecryptionFailed);
    };
    let hk = Hkdf::<Sha256>::new(None, &fek);
    let mut output = Vec::new();
    stream_decrypt_payload(
        &envelope.header.algorithm,
        envelope.header.version,
        &mut cursor,
        &mut output,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        None,
    )?;
    Ok(output)
}

pub fn decrypt_memory_keypair(
    data: &[u8],
    priv_key: &HybridPrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    let mut cursor = std::io::Cursor::new(data);
    let envelope = read_envelope(&mut cursor)?;
    let fek = unwrap_keypair_file_key(&envelope, priv_key)?;
    let hk = Hkdf::<Sha256>::new(None, &fek);
    let mut output = Vec::new();
    stream_decrypt_payload(
        &envelope.header.algorithm,
        envelope.header.version,
        &mut cursor,
        &mut output,
        &hk,
        &envelope.nonce,
        envelope.secondary_nonce,
        &envelope.aad_hash,
        envelope.plaintext_len,
        None,
    )?;
    Ok(output)
}

#[cfg(test)]
mod tests;

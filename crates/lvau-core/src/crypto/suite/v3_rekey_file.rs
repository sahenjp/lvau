//! Mutable v3 recipient and password operations.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

use lvau_protocol::envelope_v3::{
    V3MutableEnvelope, V3MutableSlot, V3_MAGIC, V3_MUTABLE_ENVELOPE_REVISION, V3_VERSION,
};
use secrecy::SecretString;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use super::file::{
    self, decrypt_payload_frames, envelope_commitment, file_revision, profile_costs, V3FileRevision,
};
use super::{hybrid, mlkem, mutable_file};
use crate::crypto::keys::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::CryptoError;

#[derive(Clone, Copy)]
enum Credential<'a> {
    Password(&'a SecretString),
    Keypair(&'a HybridPrivateKey),
}

struct AuthenticatedFile {
    input: File,
    envelope: V3MutableEnvelope,
    root_key: Zeroizing<[u8; 32]>,
    password_profile: Option<u8>,
    payload_offset: u64,
    revision: V3FileRevision,
}

fn authenticate(
    input_path: &Path,
    credential: Credential<'_>,
) -> Result<AuthenticatedFile, CryptoError> {
    match file_revision(input_path)? {
        V3FileRevision::HpkeRecipients => Err(CryptoError::Validation(
            "v3 HPKE recipient envelopes cannot be updated",
        )),
        V3FileRevision::LegacyPassword => {
            let Credential::Password(password) = credential else {
                return Err(CryptoError::Validation(
                    "private-key rekeying requires a v3 mutable envelope",
                ));
            };
            let mut input = File::open(input_path)?;
            let (legacy, serialized) = file::read_envelope(&mut input)?;
            let costs = file::validate_envelope(&legacy)?;
            let suite = file::suite_from_id(legacy.suite_id)?;
            let root_key = file::unwrap_root_key(&legacy, password, costs)
                .map_err(|_| CryptoError::DecryptionFailed)?;
            let payload_offset = input.stream_position()?;
            let binding = envelope_commitment(&root_key, suite, &serialized)?;
            decrypt_payload_frames(
                &mut input,
                &mut io::sink(),
                legacy.plaintext_len,
                &legacy.payload_base_nonce,
                &root_key,
                &binding,
                suite,
                None,
            )?;
            Ok(AuthenticatedFile {
                input,
                envelope: V3MutableEnvelope {
                    magic: V3_MAGIC,
                    version: V3_VERSION,
                    envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
                    payload_suite_id: legacy.suite_id,
                    payload_base_nonce: legacy.payload_base_nonce,
                    plaintext_len: legacy.plaintext_len,
                    payload_binding: binding,
                    slots: Vec::new(),
                    header_authenticator: [0; 32],
                },
                root_key,
                password_profile: Some(legacy.profile_id),
                payload_offset,
                revision: V3FileRevision::LegacyPassword,
            })
        }
        V3FileRevision::MutableSlots => {
            let (mut input, envelope, _) = mutable_file::read_file(input_path)?;
            let password_profile = envelope.slots.iter().find_map(|slot| match slot {
                V3MutableSlot::Password(slot) => Some(slot.profile_id),
                _ => None,
            });
            let root_key = unwrap_credential(&envelope, credential)?;
            mutable_file::verify_header(&root_key, &envelope)?;
            let payload_offset = input.stream_position()?;
            let suite = file::suite_from_id(envelope.payload_suite_id)?;
            decrypt_payload_frames(
                &mut input,
                &mut io::sink(),
                envelope.plaintext_len,
                &envelope.payload_base_nonce,
                &root_key,
                &envelope.payload_binding,
                suite,
                None,
            )?;
            Ok(AuthenticatedFile {
                input,
                envelope,
                root_key,
                password_profile,
                payload_offset,
                revision: V3FileRevision::MutableSlots,
            })
        }
    }
}

fn unwrap_credential(
    envelope: &V3MutableEnvelope,
    credential: Credential<'_>,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    match credential {
        Credential::Password(password) => mutable_file::unwrap_for_password(envelope, password),
        Credential::Keypair(private_key) => {
            mutable_file::unwrap_for_private_key(envelope, private_key)
        }
    }
    .map_err(|_| CryptoError::DecryptionFailed)
}

fn rewrite(
    mut authenticated: AuthenticatedFile,
    output_path: &Path,
    verification_credential: Credential<'_>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    authenticated
        .envelope
        .slots
        .sort_by_key(mutable_file::slot_order);
    mutable_file::seal_header(&authenticated.root_key, &mut authenticated.envelope)?;
    let envelope_bytes = mutable_file::encode_envelope(&authenticated.envelope)?;

    let mut output = NamedTempFile::new_in(mutable_file::parent_directory(output_path))?;
    mutable_file::write_length_and_envelope(&mut output, &envelope_bytes)?;
    authenticated
        .input
        .seek(SeekFrom::Start(authenticated.payload_offset))?;
    io::copy(&mut authenticated.input, &mut output)?;
    output.as_file_mut().flush()?;

    output.as_file_mut().seek(SeekFrom::Start(0))?;
    let (envelope, _) = mutable_file::read_envelope(output.as_file_mut())?;
    let root_key = unwrap_credential(&envelope, verification_credential)?;
    mutable_file::verify_header(&root_key, &envelope)?;
    let suite = file::suite_from_id(envelope.payload_suite_id)?;
    decrypt_payload_frames(
        output.as_file_mut(),
        &mut io::sink(),
        envelope.plaintext_len,
        &envelope.payload_base_nonce,
        &root_key,
        &envelope.payload_binding,
        suite,
        None,
    )?;
    output.as_file().sync_all()?;
    mutable_file::persist(output, output_path, replace_existing)
}

pub fn add_mlkem_recipient(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    add_mlkem_recipient_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        recipient,
        replace_existing,
    )
}

pub fn add_mlkem_recipient_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    add_mlkem_recipient_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        recipient,
        replace_existing,
    )
}

fn add_mlkem_recipient_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut authenticated = authenticate(input_path, credential)?;
    let key_id = mlkem::recipient_key_id(&recipient.mlkem);
    if authenticated
        .envelope
        .slots
        .iter()
        .any(|slot| matches!(slot, V3MutableSlot::MlKem768(slot) if slot.key_id == key_id))
    {
        return Err(CryptoError::Validation("Duplicate v3 ML-KEM recipient"));
    }
    if authenticated.revision == V3FileRevision::LegacyPassword {
        let Credential::Password(current_password) = credential else {
            unreachable!();
        };
        let password_slot = mutable_file::wrap_password_slot(
            &authenticated.envelope,
            &authenticated.root_key,
            current_password,
            authenticated.password_profile.unwrap(),
        )?;
        authenticated
            .envelope
            .slots
            .push(V3MutableSlot::Password(password_slot));
    }
    let context = mutable_file::slot_context(&authenticated.envelope)?;
    authenticated
        .envelope
        .slots
        .push(V3MutableSlot::MlKem768(mlkem::wrap_root_key(
            &authenticated.root_key,
            &recipient.mlkem,
            &context,
        )?));
    rewrite(authenticated, output_path, credential, replace_existing)
}

pub fn remove_mlkem_recipient(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    remove_mlkem_recipient_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        recipient,
        replace_existing,
    )
}

pub fn remove_mlkem_recipient_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    remove_mlkem_recipient_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        recipient,
        replace_existing,
    )
}

fn remove_mlkem_recipient_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut authenticated = authenticate(input_path, credential)?;
    if authenticated.revision != V3FileRevision::MutableSlots {
        return Err(CryptoError::Validation(
            "ML-KEM recipients can only be removed from v3 mutable envelopes",
        ));
    }
    let key_id = mlkem::recipient_key_id(&recipient.mlkem);
    if !authenticated
        .envelope
        .slots
        .iter()
        .any(|slot| matches!(slot, V3MutableSlot::MlKem768(slot) if slot.key_id == key_id))
    {
        return Err(CryptoError::Validation("v3 ML-KEM recipient was not found"));
    }
    let before = authenticated.envelope.slots.len();
    authenticated
        .envelope
        .slots
        .retain(|slot| !matches!(slot, V3MutableSlot::MlKem768(slot) if slot.key_id == key_id));
    if authenticated.envelope.slots.is_empty() {
        return Err(CryptoError::Validation(
            "v3 envelope must retain at least one credential slot",
        ));
    }
    if let Credential::Keypair(private_key) = credential {
        if mutable_file::unwrap_for_private_key(&authenticated.envelope, private_key).is_err() {
            return Err(CryptoError::Validation(
                "updated recipient table has no slot usable by the current private key",
            ));
        }
    }
    debug_assert_eq!(authenticated.envelope.slots.len() + 1, before);
    rewrite(authenticated, output_path, credential, replace_existing)
}

pub fn add_x25519_recipient(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    add_x25519_recipient_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        recipient,
        replace_existing,
    )
}

pub fn add_x25519_recipient_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    add_x25519_recipient_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        recipient,
        replace_existing,
    )
}

fn add_x25519_recipient_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut authenticated = authenticate(input_path, credential)?;
    let context = mutable_file::slot_context(&authenticated.envelope)?;
    let recipient_slot = mutable_file::wrap_x25519_root_key(
        &authenticated.root_key,
        recipient.x25519.as_bytes(),
        &context,
    )?;
    if authenticated.envelope.slots.iter().any(
        |slot| matches!(slot, V3MutableSlot::X25519Hpke(slot) if slot.key_id == recipient_slot.key_id),
    ) {
        return Err(CryptoError::Validation("Duplicate v3 X25519 recipient"));
    }
    if authenticated.revision == V3FileRevision::LegacyPassword {
        let Credential::Password(current_password) = credential else {
            unreachable!();
        };
        let password_slot = mutable_file::wrap_password_slot(
            &authenticated.envelope,
            &authenticated.root_key,
            current_password,
            authenticated.password_profile.unwrap(),
        )?;
        authenticated
            .envelope
            .slots
            .push(V3MutableSlot::Password(password_slot));
    }
    authenticated
        .envelope
        .slots
        .push(V3MutableSlot::X25519Hpke(recipient_slot));
    rewrite(authenticated, output_path, credential, replace_existing)
}

pub fn remove_x25519_recipient(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    remove_x25519_recipient_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        recipient,
        replace_existing,
    )
}

pub fn remove_x25519_recipient_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    remove_x25519_recipient_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        recipient,
        replace_existing,
    )
}

fn remove_x25519_recipient_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut authenticated = authenticate(input_path, credential)?;
    if authenticated.revision != V3FileRevision::MutableSlots {
        return Err(CryptoError::Validation(
            "X25519 recipients can only be removed from v3 mutable envelopes",
        ));
    }
    let key_id = mutable_file::x25519_key_id(recipient.x25519.as_bytes());
    if !authenticated
        .envelope
        .slots
        .iter()
        .any(|slot| matches!(slot, V3MutableSlot::X25519Hpke(slot) if slot.key_id == key_id))
    {
        return Err(CryptoError::Validation("v3 X25519 recipient was not found"));
    }
    let before = authenticated.envelope.slots.len();
    authenticated
        .envelope
        .slots
        .retain(|slot| !matches!(slot, V3MutableSlot::X25519Hpke(slot) if slot.key_id == key_id));
    if authenticated.envelope.slots.is_empty() {
        return Err(CryptoError::Validation(
            "v3 envelope must retain at least one credential slot",
        ));
    }
    if let Credential::Keypair(private_key) = credential {
        if mutable_file::unwrap_for_private_key(&authenticated.envelope, private_key).is_err() {
            return Err(CryptoError::Validation(
                "updated recipient table has no slot usable by the current private key",
            ));
        }
    }
    debug_assert_eq!(authenticated.envelope.slots.len() + 1, before);
    rewrite(authenticated, output_path, credential, replace_existing)
}

pub fn add_hybrid_recipient(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    add_hybrid_recipient_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        recipient,
        replace_existing,
    )
}

pub fn add_hybrid_recipient_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    add_hybrid_recipient_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        recipient,
        replace_existing,
    )
}

fn add_hybrid_recipient_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut authenticated = authenticate(input_path, credential)?;
    let context = mutable_file::slot_context(&authenticated.envelope)?;
    let recipient_slot = hybrid::wrap_root_key(&authenticated.root_key, recipient, &context)?;
    if authenticated.envelope.slots.iter().any(
        |slot| {
            matches!(slot, V3MutableSlot::HybridX25519MlKem768(slot) if slot.key_id == recipient_slot.key_id)
        },
    ) {
        return Err(CryptoError::Validation("Duplicate v3 hybrid recipient"));
    }
    if authenticated.revision == V3FileRevision::LegacyPassword {
        let Credential::Password(current_password) = credential else {
            unreachable!();
        };
        let password_slot = mutable_file::wrap_password_slot(
            &authenticated.envelope,
            &authenticated.root_key,
            current_password,
            authenticated.password_profile.unwrap(),
        )?;
        authenticated
            .envelope
            .slots
            .push(V3MutableSlot::Password(password_slot));
    }
    authenticated
        .envelope
        .slots
        .push(V3MutableSlot::HybridX25519MlKem768(recipient_slot));
    rewrite(authenticated, output_path, credential, replace_existing)
}

pub fn remove_hybrid_recipient(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    remove_hybrid_recipient_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        recipient,
        replace_existing,
    )
}

pub fn remove_hybrid_recipient_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    remove_hybrid_recipient_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        recipient,
        replace_existing,
    )
}

fn remove_hybrid_recipient_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    recipient: &HybridPublicKey,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    let mut authenticated = authenticate(input_path, credential)?;
    if authenticated.revision != V3FileRevision::MutableSlots {
        return Err(CryptoError::Validation(
            "Hybrid recipients can only be removed from v3 mutable envelopes",
        ));
    }
    let key_id = hybrid::recipient_key_id(&recipient.x25519.to_bytes(), &recipient.mlkem);
    if !authenticated.envelope.slots.iter().any(
        |slot| matches!(slot, V3MutableSlot::HybridX25519MlKem768(slot) if slot.key_id == key_id),
    ) {
        return Err(CryptoError::Validation("v3 hybrid recipient was not found"));
    }
    let before = authenticated.envelope.slots.len();
    authenticated.envelope.slots.retain(
        |slot| !matches!(slot, V3MutableSlot::HybridX25519MlKem768(slot) if slot.key_id == key_id),
    );
    if authenticated.envelope.slots.is_empty() {
        return Err(CryptoError::Validation(
            "v3 envelope must retain at least one credential slot",
        ));
    }
    if let Credential::Keypair(private_key) = credential {
        if mutable_file::unwrap_for_private_key(&authenticated.envelope, private_key).is_err() {
            return Err(CryptoError::Validation(
                "updated recipient table has no slot usable by the current private key",
            ));
        }
    }
    debug_assert_eq!(authenticated.envelope.slots.len() + 1, before);
    rewrite(authenticated, output_path, credential, replace_existing)
}

pub fn change_password(
    input_path: &Path,
    output_path: &Path,
    current_password: SecretString,
    new_password: SecretString,
    profile_id: Option<u8>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    change_password_inner(
        input_path,
        output_path,
        Credential::Password(&current_password),
        new_password,
        profile_id,
        replace_existing,
    )
}

pub fn change_password_with_keypair(
    input_path: &Path,
    output_path: &Path,
    current_keypair: &HybridPrivateKey,
    new_password: SecretString,
    profile_id: Option<u8>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    change_password_inner(
        input_path,
        output_path,
        Credential::Keypair(current_keypair),
        new_password,
        profile_id,
        replace_existing,
    )
}

fn change_password_inner(
    input_path: &Path,
    output_path: &Path,
    credential: Credential<'_>,
    new_password: SecretString,
    profile_id: Option<u8>,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    if let Some(profile_id) = profile_id {
        profile_costs(profile_id)?;
    }
    let mut authenticated = authenticate(input_path, credential)?;
    let profile_id = profile_id.or(authenticated.password_profile).unwrap_or(1);
    let password_slot = mutable_file::wrap_password_slot(
        &authenticated.envelope,
        &authenticated.root_key,
        &new_password,
        profile_id,
    )?;
    authenticated
        .envelope
        .slots
        .retain(|slot| !matches!(slot, V3MutableSlot::Password(_)));
    authenticated
        .envelope
        .slots
        .push(V3MutableSlot::Password(password_slot));
    rewrite(
        authenticated,
        output_path,
        Credential::Password(&new_password),
        replace_existing,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use lvau_protocol::envelope::SecurityProfile;
    use tempfile::tempdir;

    use super::*;
    use crate::crypto::keys::generate_keypair;

    fn password(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn payload_bytes(path: &Path) -> Vec<u8> {
        let bytes = fs::read(path).unwrap();
        let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        bytes[4 + length..].to_vec()
    }

    fn legacy_file(directory: &Path) -> (std::path::PathBuf, Vec<u8>) {
        let plaintext = directory.join("plaintext");
        let encrypted = directory.join("legacy.lvau");
        fs::write(&plaintext, b"payload preserved across key updates").unwrap();
        file::encrypt_file_password(
            &plaintext,
            &encrypted,
            password("old"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&encrypted).unwrap();
        (encrypted, original)
    }

    #[test]
    fn add_recipient_converts_legacy_and_preserves_source_and_ciphertext() {
        let directory = tempdir().unwrap();
        let (input, original) = legacy_file(directory.path());
        let output = directory.path().join("added.lvau");
        let output_again = directory.path().join("added-again.lvau");
        let password_output = directory.path().join("password.out");
        let key_output = directory.path().join("key.out");
        let (private, public) = generate_keypair();
        let (second_private, second_public) = generate_keypair();

        assert!(matches!(
            add_mlkem_recipient_with_keypair(&input, &output, &private, &public, false),
            Err(CryptoError::Validation(
                "private-key rekeying requires a v3 mutable envelope"
            ))
        ));
        assert!(!output.exists());

        add_mlkem_recipient(&input, &output, password("old"), &public, false).unwrap();

        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(payload_bytes(&output), payload_bytes(&input));
        mutable_file::decrypt_file_password(
            &output,
            &password_output,
            password("old"),
            false,
            None,
        )
        .unwrap();
        mutable_file::decrypt_file_keypair(&output, &key_output, &private, false, None).unwrap();
        assert_eq!(
            fs::read(password_output).unwrap(),
            b"payload preserved across key updates"
        );
        assert_eq!(
            fs::read(key_output).unwrap(),
            b"payload preserved across key updates"
        );

        let (_, first_envelope, _) = mutable_file::read_file(&output).unwrap();
        add_mlkem_recipient(
            &output,
            &output_again,
            password("old"),
            &second_public,
            false,
        )
        .unwrap();
        let (_, second_envelope, _) = mutable_file::read_file(&output_again).unwrap();
        assert!(first_envelope
            .slots
            .iter()
            .all(|slot| second_envelope.slots.contains(slot)));
        assert_eq!(payload_bytes(&output_again), payload_bytes(&input));
        mutable_file::verify_file_keypair(&output_again, &private, None).unwrap();
        mutable_file::verify_file_keypair(&output_again, &second_private, None).unwrap();

        let duplicate = directory.path().join("duplicate.lvau");
        assert!(matches!(
            add_mlkem_recipient(&output_again, &duplicate, password("old"), &public, false,),
            Err(CryptoError::Validation("Duplicate v3 ML-KEM recipient"))
        ));
        assert!(!duplicate.exists());
    }

    #[test]
    fn remove_recipient_rejects_missing_match_and_keeps_password_access() {
        let directory = tempdir().unwrap();
        let (legacy, _) = legacy_file(directory.path());
        let added = directory.path().join("added.lvau");
        let removed = directory.path().join("removed.lvau");
        let missing = directory.path().join("missing.lvau");
        let (private, public) = generate_keypair();
        let (_, other_public) = generate_keypair();
        add_mlkem_recipient(&legacy, &added, password("old"), &public, false).unwrap();
        let added_bytes = fs::read(&added).unwrap();

        remove_mlkem_recipient(&added, &removed, password("old"), &public, false).unwrap();

        assert_eq!(fs::read(&added).unwrap(), added_bytes);
        assert_eq!(payload_bytes(&removed), payload_bytes(&added));
        mutable_file::verify_file_password(&removed, password("old"), None).unwrap();
        assert!(mutable_file::verify_file_keypair(&removed, &private, None).is_err());
        assert!(matches!(
            remove_mlkem_recipient(&removed, &missing, password("old"), &other_public, false,),
            Err(CryptoError::Validation("v3 ML-KEM recipient was not found"))
        ));
        assert!(!missing.exists());
    }

    #[test]
    fn add_x25519_recipient_decrypts_with_key_and_password() {
        let directory = tempdir().unwrap();
        let (input, original) = legacy_file(directory.path());
        let output = directory.path().join("x25519-added.lvau");
        let password_output = directory.path().join("password.out");
        let key_output = directory.path().join("key.out");
        let (private, public) = generate_keypair();

        add_x25519_recipient(&input, &output, password("old"), &public, false).unwrap();

        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(payload_bytes(&output), payload_bytes(&input));
        mutable_file::decrypt_file_password(
            &output,
            &password_output,
            password("old"),
            false,
            None,
        )
        .unwrap();
        mutable_file::decrypt_file_keypair(&output, &key_output, &private, false, None).unwrap();
        assert_eq!(
            fs::read(password_output).unwrap(),
            fs::read(&key_output).unwrap()
        );
        assert_eq!(
            fs::read(key_output).unwrap(),
            b"payload preserved across key updates"
        );
        let duplicate = directory.path().join("duplicate.lvau");
        assert!(matches!(
            add_x25519_recipient(&output, &duplicate, password("old"), &public, false),
            Err(CryptoError::Validation("Duplicate v3 X25519 recipient"))
        ));
        assert!(!duplicate.exists());
    }

    #[test]
    fn remove_x25519_recipient_keeps_password_and_source() {
        let directory = tempdir().unwrap();
        let (input, _) = legacy_file(directory.path());
        let added = directory.path().join("x25519-added.lvau");
        let removed = directory.path().join("x25519-removed.lvau");
        let missing = directory.path().join("missing.lvau");
        let (private, public) = generate_keypair();
        let (_, other_public) = generate_keypair();
        add_x25519_recipient(&input, &added, password("old"), &public, false).unwrap();
        let added_bytes = fs::read(&added).unwrap();

        remove_x25519_recipient(&added, &removed, password("old"), &public, false).unwrap();

        assert_eq!(fs::read(&added).unwrap(), added_bytes);
        assert_eq!(payload_bytes(&removed), payload_bytes(&added));
        mutable_file::verify_file_password(&removed, password("old"), None).unwrap();
        assert!(mutable_file::verify_file_keypair(&removed, &private, None).is_err());
        assert!(matches!(
            remove_x25519_recipient(&removed, &missing, password("old"), &other_public, false,),
            Err(CryptoError::Validation("v3 X25519 recipient was not found"))
        ));
        assert!(!missing.exists());
    }

    #[test]
    fn same_private_key_can_remove_one_slot_when_its_other_slot_survives() {
        let directory = tempdir().unwrap();
        let (legacy, _) = legacy_file(directory.path());
        let with_mlkem = directory.path().join("with-mlkem.lvau");
        let with_both = directory.path().join("with-both.lvau");
        let without_mlkem = directory.path().join("without-mlkem.lvau");
        let without_x25519 = directory.path().join("without-x25519.lvau");
        let (private, public) = generate_keypair();

        add_mlkem_recipient(&legacy, &with_mlkem, password("old"), &public, false).unwrap();
        add_x25519_recipient(&with_mlkem, &with_both, password("old"), &public, false).unwrap();

        remove_mlkem_recipient_with_keypair(&with_both, &without_mlkem, &private, &public, false)
            .unwrap();
        mutable_file::verify_file_keypair(&without_mlkem, &private, None).unwrap();

        remove_x25519_recipient_with_keypair(&with_both, &without_x25519, &private, &public, false)
            .unwrap();
        mutable_file::verify_file_keypair(&without_x25519, &private, None).unwrap();
        assert_eq!(payload_bytes(&without_mlkem), payload_bytes(&with_both));
        assert_eq!(payload_bytes(&without_x25519), payload_bytes(&with_both));
    }

    #[test]
    fn change_password_refreshes_wrapping_and_preserves_profile_or_uses_override() {
        let directory = tempdir().unwrap();
        let (legacy, original) = legacy_file(directory.path());
        let changed = directory.path().join("changed.lvau");
        let changed_again = directory.path().join("changed-again.lvau");

        change_password(
            &legacy,
            &changed,
            password("old"),
            password("new"),
            None,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(&legacy).unwrap(), original);
        assert_eq!(payload_bytes(&changed), payload_bytes(&legacy));
        assert!(matches!(
            mutable_file::verify_file_password(&changed, password("old"), None),
            Err(CryptoError::DecryptionFailed)
        ));
        mutable_file::verify_file_password(&changed, password("new"), None).unwrap();
        let (_, first, _) = mutable_file::read_file(&changed).unwrap();
        let first_password = first
            .slots
            .iter()
            .find_map(|slot| match slot {
                V3MutableSlot::Password(slot) => Some(slot),
                _ => None,
            })
            .unwrap();
        assert_eq!(first_password.profile_id, 0);

        change_password(
            &changed,
            &changed_again,
            password("new"),
            password("newest"),
            Some(1),
            false,
        )
        .unwrap();
        let (_, second, _) = mutable_file::read_file(&changed_again).unwrap();
        let second_password = second
            .slots
            .iter()
            .find_map(|slot| match slot {
                V3MutableSlot::Password(slot) => Some(slot),
                _ => None,
            })
            .unwrap();
        assert_eq!(second_password.profile_id, 1);
        assert_ne!(first_password.salt, second_password.salt);
        assert_ne!(
            first_password.wrapping_nonce,
            second_password.wrapping_nonce
        );
        assert_eq!(payload_bytes(&changed_again), payload_bytes(&legacy));
        assert!(mutable_file::verify_file_password(&changed_again, password("new"), None).is_err());
        mutable_file::verify_file_password(&changed_again, password("newest"), None).unwrap();
    }

    #[test]
    fn pure_mlkem_file_can_be_rekeyed_with_its_private_key() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let input = directory.path().join("mlkem.lvau");
        let added = directory.path().join("added.lvau");
        let removed = directory.path().join("removed.lvau");
        let changed = directory.path().join("changed.lvau");
        let (first_private, first_public) = generate_keypair();
        let (second_private, second_public) = generate_keypair();
        let (wrong_private, _) = generate_keypair();
        fs::write(&plaintext, b"pure ML-KEM payload").unwrap();
        mutable_file::encrypt_file_mlkem(
            &plaintext,
            &input,
            std::slice::from_ref(&first_public),
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&input).unwrap();

        let wrong_output = directory.path().join("wrong.lvau");
        assert!(matches!(
            add_mlkem_recipient_with_keypair(
                &input,
                &wrong_output,
                &wrong_private,
                &second_public,
                false,
            ),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(!wrong_output.exists());

        add_mlkem_recipient_with_keypair(&input, &added, &first_private, &second_public, false)
            .unwrap();
        assert_eq!(fs::read(&input).unwrap(), original);
        assert_eq!(payload_bytes(&added), payload_bytes(&input));
        mutable_file::verify_file_keypair(&added, &first_private, None).unwrap();
        mutable_file::verify_file_keypair(&added, &second_private, None).unwrap();

        let added_bytes = fs::read(&added).unwrap();
        remove_mlkem_recipient_with_keypair(
            &added,
            &removed,
            &first_private,
            &second_public,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(&added).unwrap(), added_bytes);
        assert_eq!(payload_bytes(&removed), payload_bytes(&input));
        mutable_file::verify_file_keypair(&removed, &first_private, None).unwrap();
        assert!(mutable_file::verify_file_keypair(&removed, &second_private, None).is_err());

        change_password_with_keypair(
            &removed,
            &changed,
            &first_private,
            password("new"),
            None,
            false,
        )
        .unwrap();
        assert_eq!(payload_bytes(&changed), payload_bytes(&input));
        mutable_file::verify_file_keypair(&changed, &first_private, None).unwrap();
        mutable_file::verify_file_password(&changed, password("new"), None).unwrap();
        assert!(mutable_file::verify_file_password(&changed, password("wrong"), None).is_err());
        let (_, envelope, _) = mutable_file::read_file(&changed).unwrap();
        assert!(envelope
            .slots
            .iter()
            .any(|slot| matches!(slot, V3MutableSlot::Password(slot) if slot.profile_id == 1)));

        let tampered = directory.path().join("tampered.lvau");
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&tampered, damaged).unwrap();
        let tampered_output = directory.path().join("tampered-output.lvau");
        assert!(add_mlkem_recipient_with_keypair(
            &tampered,
            &tampered_output,
            &first_private,
            &second_public,
            false,
        )
        .is_err());
        assert!(!tampered_output.exists());

        let malformed = directory.path().join("malformed.lvau");
        fs::write(&malformed, [0xff; 12]).unwrap();
        let malformed_output = directory.path().join("malformed-output.lvau");
        assert!(change_password_with_keypair(
            &malformed,
            &malformed_output,
            &first_private,
            password("new"),
            None,
            false,
        )
        .is_err());
        assert!(!malformed_output.exists());

        let existing = directory.path().join("existing.lvau");
        fs::write(&existing, b"keep me").unwrap();
        assert!(matches!(
            add_mlkem_recipient_with_keypair(
                &input,
                &existing,
                &first_private,
                &second_public,
                false,
            ),
            Err(CryptoError::OutputExists)
        ));
        assert_eq!(fs::read(existing).unwrap(), b"keep me");
    }

    #[test]
    fn private_key_cannot_remove_its_only_mlkem_slot() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let input = directory.path().join("mlkem.lvau");
        let output = directory.path().join("removed.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"payload").unwrap();
        mutable_file::encrypt_file_mlkem(
            &plaintext,
            &input,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();

        assert!(matches!(
            remove_mlkem_recipient_with_keypair(&input, &output, &private, &public, false),
            Err(CryptoError::Validation(
                "v3 envelope must retain at least one credential slot"
            ))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn failures_never_publish_or_replace_existing_output() {
        let directory = tempdir().unwrap();
        let (input, original) = legacy_file(directory.path());
        let (_, public) = generate_keypair();
        let wrong_output = directory.path().join("wrong.lvau");
        assert!(matches!(
            add_mlkem_recipient(&input, &wrong_output, password("wrong"), &public, false),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(!wrong_output.exists());

        let malformed = directory.path().join("malformed.lvau");
        fs::write(&malformed, [0xff; 12]).unwrap();
        let malformed_output = directory.path().join("malformed-output.lvau");
        assert!(change_password(
            &malformed,
            &malformed_output,
            password("old"),
            password("new"),
            None,
            false,
        )
        .is_err());
        assert!(!malformed_output.exists());

        let tampered = directory.path().join("tampered.lvau");
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&tampered, damaged).unwrap();
        let tampered_output = directory.path().join("tampered-output.lvau");
        assert!(change_password(
            &tampered,
            &tampered_output,
            password("old"),
            password("new"),
            None,
            false,
        )
        .is_err());
        assert!(!tampered_output.exists());

        let mutable = directory.path().join("mutable.lvau");
        change_password(
            &input,
            &mutable,
            password("old"),
            password("current"),
            None,
            false,
        )
        .unwrap();
        let (_, mut envelope, _) = mutable_file::read_file(&mutable).unwrap();
        envelope.header_authenticator[0] ^= 1;
        let encoded = mutable_file::encode_envelope(&envelope).unwrap();
        let header_tampered = directory.path().join("header-tampered.lvau");
        let mut bytes = (encoded.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&encoded);
        bytes.extend_from_slice(&payload_bytes(&mutable));
        fs::write(&header_tampered, bytes).unwrap();
        let header_output = directory.path().join("header-output.lvau");
        assert!(matches!(
            change_password(
                &header_tampered,
                &header_output,
                password("current"),
                password("new"),
                None,
                false,
            ),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(!header_output.exists());

        let existing = directory.path().join("existing.lvau");
        fs::write(&existing, b"keep me").unwrap();
        assert!(matches!(
            change_password(
                &input,
                &existing,
                password("old"),
                password("new"),
                None,
                false,
            ),
            Err(CryptoError::OutputExists)
        ));
        assert_eq!(fs::read(existing).unwrap(), b"keep me");
        assert_eq!(fs::read(input).unwrap(), original);
    }

    #[test]
    fn hpke_revision_is_rejected_explicitly() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let hpke = directory.path().join("hpke.lvau");
        let output = directory.path().join("output.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"payload").unwrap();
        super::super::hpke_file::encrypt_file_keypairs(
            &plaintext,
            &hpke,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();

        assert!(matches!(
            add_mlkem_recipient(&hpke, &output, password("unused"), &public, false),
            Err(CryptoError::Validation(
                "v3 HPKE recipient envelopes cannot be updated"
            ))
        ));
        assert!(!output.exists());
        assert!(matches!(
            add_mlkem_recipient_with_keypair(&hpke, &output, &private, &public, false),
            Err(CryptoError::Validation(
                "v3 HPKE recipient envelopes cannot be updated"
            ))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn layered_legacy_converts_to_a4_and_supports_slot_updates() {
        use crate::crypto::suite::V3SuiteId;

        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let legacy = directory.path().join("legacy-layered.lvau");
        let added = directory.path().join("added.lvau");
        let changed = directory.path().join("changed.lvau");
        let removed = directory.path().join("removed.lvau");
        fs::write(&plaintext, b"layered payload preserved across key updates").unwrap();
        file::encrypt_file_password_with_suite(
            &plaintext,
            &legacy,
            password("old"),
            SecurityProfile::Fast,
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&legacy).unwrap();
        let (private, public) = generate_keypair();

        add_mlkem_recipient(&legacy, &added, password("old"), &public, false).unwrap();
        assert_eq!(fs::read(&legacy).unwrap(), original);
        let (_, envelope, _) = mutable_file::read_file(&added).unwrap();
        assert_eq!(
            envelope.payload_suite_id,
            lvau_protocol::envelope_v3::V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305
        );
        assert_eq!(payload_bytes(&added), payload_bytes(&legacy));

        let password_output = directory.path().join("password.out");
        let key_output = directory.path().join("key.out");
        mutable_file::decrypt_file_password(&added, &password_output, password("old"), false, None)
            .unwrap();
        mutable_file::decrypt_file_keypair(&added, &key_output, &private, false, None).unwrap();
        assert_eq!(
            fs::read(password_output).unwrap(),
            b"layered payload preserved across key updates"
        );
        assert_eq!(
            fs::read(key_output).unwrap(),
            b"layered payload preserved across key updates"
        );

        change_password(
            &added,
            &changed,
            password("old"),
            password("new"),
            None,
            false,
        )
        .unwrap();
        mutable_file::verify_file_password(&changed, password("new"), None).unwrap();
        assert!(mutable_file::verify_file_password(&changed, password("old"), None).is_err());
        mutable_file::verify_file_keypair(&changed, &private, None).unwrap();

        remove_mlkem_recipient(&changed, &removed, password("new"), &public, false).unwrap();
        assert_eq!(payload_bytes(&removed), payload_bytes(&legacy));
        mutable_file::decrypt_file_password(
            &removed,
            &directory.path().join("removed.out"),
            password("new"),
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            fs::read(directory.path().join("removed.out")).unwrap(),
            b"layered payload preserved across key updates"
        );
        assert!(mutable_file::verify_file_keypair(&removed, &private, None).is_err());
    }

    #[test]
    fn hybrid_recipient_add_remove_roundtrip() {
        let directory = tempdir().unwrap();
        let (input, _) = legacy_file(directory.path());
        let added = directory.path().join("added.lvau");
        let removed = directory.path().join("removed.lvau");
        let (private, public) = generate_keypair();
        let (_, other_public) = generate_keypair();

        add_hybrid_recipient(&input, &added, password("old"), &public, false).unwrap();
        assert_eq!(payload_bytes(&added), payload_bytes(&input));

        let password_output = directory.path().join("password.out");
        let key_output = directory.path().join("key.out");
        mutable_file::decrypt_file_password(&added, &password_output, password("old"), false, None)
            .unwrap();
        mutable_file::decrypt_file_keypair(&added, &key_output, &private, false, None).unwrap();
        assert_eq!(
            fs::read(password_output).unwrap(),
            b"payload preserved across key updates"
        );
        assert_eq!(
            fs::read(key_output).unwrap(),
            b"payload preserved across key updates"
        );

        assert!(matches!(
            add_hybrid_recipient(
                &added,
                &directory.path().join("dup.lvau"),
                password("old"),
                &public,
                false
            ),
            Err(CryptoError::Validation("Duplicate v3 hybrid recipient"))
        ));

        remove_hybrid_recipient(&added, &removed, password("old"), &public, false).unwrap();
        assert_eq!(payload_bytes(&removed), payload_bytes(&input));
        mutable_file::verify_file_password(&removed, password("old"), None).unwrap();
        assert!(mutable_file::verify_file_keypair(&removed, &private, None).is_err());

        assert!(matches!(
            remove_hybrid_recipient(
                &removed,
                &directory.path().join("missing.lvau"),
                password("old"),
                &other_public,
                false
            ),
            Err(CryptoError::Validation("v3 hybrid recipient was not found"))
        ));
    }
}

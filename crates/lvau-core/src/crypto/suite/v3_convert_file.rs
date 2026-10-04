//! A3-to-A4 conversion while preserving authenticated payload frame bytes.

use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

use lvau_protocol::envelope_v3::{
    V3MutableEnvelope, V3MutableSlot, V3_MAGIC, V3_MUTABLE_ENVELOPE_REVISION,
    V3_MUTABLE_MAX_RECIPIENTS, V3_SUITE_XCHACHA20_POLY1305, V3_VERSION,
};
use tempfile::NamedTempFile;
use x25519_dalek::PublicKey as X25519PublicKey;

use super::{file, hpke_file, mutable_file, V3SuiteId};
use crate::crypto::keys::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::CryptoError;

fn same_source_and_output(input_path: &Path, output_path: &Path) -> Result<bool, CryptoError> {
    if input_path == output_path {
        return Ok(true);
    }
    let input = fs::canonicalize(input_path)?;
    if output_path.exists()
        && same_file::is_same_file(input_path, output_path).map_err(CryptoError::Io)?
    {
        return Ok(true);
    }
    match fs::canonicalize(output_path) {
        Ok(output) => Ok(input == output),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = output_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let Some(name) = output_path.file_name() else {
                return Ok(false);
            };
            Ok(input == fs::canonicalize(parent)?.join(name))
        }
        Err(error) => Err(error.into()),
    }
}

pub fn convert_a3_to_a4(
    input_path: &Path,
    output_path: &Path,
    source_private_key: &HybridPrivateKey,
    additional_public_keys: &[HybridPublicKey],
    replace_existing: bool,
) -> Result<(), CryptoError> {
    if same_source_and_output(input_path, output_path)? {
        return Err(CryptoError::Validation(
            "A3-to-A4 conversion requires distinct input and output paths",
        ));
    }
    if file::file_revision(input_path)? != file::V3FileRevision::HpkeRecipients {
        return Err(CryptoError::Validation(
            "A3-to-A4 conversion requires an A3 HPKE envelope",
        ));
    }

    let mut input = File::open(input_path)?;
    let (source_envelope, source_envelope_bytes) = hpke_file::read_envelope(&mut input)?;
    hpke_file::validate_envelope(&source_envelope)?;
    let root_key = hpke_file::unwrap_for_private_key(&source_envelope, source_private_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let source_commitment = file::envelope_commitment(
        &root_key,
        V3SuiteId::XChaCha20Poly1305,
        &source_envelope_bytes,
    )?;
    file::decrypt_payload_frames(
        &mut input,
        &mut io::sink(),
        source_envelope.plaintext_len,
        &source_envelope.payload_base_nonce,
        &root_key,
        &source_commitment,
        V3SuiteId::XChaCha20Poly1305,
        None,
    )?;

    let source_public = X25519PublicKey::from(&source_private_key.x25519).to_bytes();
    if additional_public_keys.len() > V3_MUTABLE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 recipient slot count is invalid",
        ));
    }
    let source_key_id = hpke_file::recipient_key_id(&source_public);
    let mut recipients = Vec::with_capacity(additional_public_keys.len() + 1);
    recipients.push((source_key_id, source_public));
    for key in additional_public_keys {
        let public = key.x25519.to_bytes();
        if !hpke_file::is_canonical_x25519(&public) {
            return Err(CryptoError::Validation(
                "Recipient X25519 public key is not canonical",
            ));
        }
        let key_id = hpke_file::recipient_key_id(&public);
        if key_id != source_key_id {
            recipients.push((key_id, public));
        }
    }
    if recipients.len() > V3_MUTABLE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 recipient slot count is invalid",
        ));
    }
    recipients.sort_by_key(|(key_id, _)| *key_id);
    if recipients.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CryptoError::Validation("Duplicate v3 X25519 recipient"));
    }
    if source_envelope.recipients.iter().any(|source| {
        recipients
            .binary_search_by_key(&source.key_id, |(key_id, _)| *key_id)
            .is_err()
    }) {
        return Err(CryptoError::Validation(
            "destination recipients do not cover every A3 recipient",
        ));
    }

    let mut destination_envelope = V3MutableEnvelope {
        magic: V3_MAGIC,
        version: V3_VERSION,
        envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
        payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
        payload_base_nonce: source_envelope.payload_base_nonce,
        plaintext_len: source_envelope.plaintext_len,
        payload_binding: source_commitment,
        slots: Vec::with_capacity(recipients.len()),
        header_authenticator: [0; 32],
    };
    let context = mutable_file::slot_context(&destination_envelope)?;
    for (_, public) in recipients {
        destination_envelope.slots.push(V3MutableSlot::X25519Hpke(
            mutable_file::wrap_x25519_root_key(&root_key, &public, &context)?,
        ));
    }
    destination_envelope
        .slots
        .sort_by_key(mutable_file::slot_order);
    mutable_file::seal_header(&root_key, &mut destination_envelope)?;
    let destination_envelope_bytes = mutable_file::encode_envelope(&destination_envelope)?;

    let mut output = NamedTempFile::new_in(mutable_file::parent_directory(output_path))?;
    mutable_file::write_length_and_envelope(&mut output, &destination_envelope_bytes)?;
    let payload_offset = 4u64
        .checked_add(source_envelope_bytes.len() as u64)
        .ok_or(CryptoError::Validation("v3 payload offset overflow"))?;
    input.seek(SeekFrom::Start(payload_offset))?;
    io::copy(&mut input, &mut output)?;
    output.as_file_mut().flush()?;

    output.as_file_mut().seek(SeekFrom::Start(0))?;
    let (staged_envelope, _) = mutable_file::read_envelope(output.as_file_mut())?;
    let staged_root_key =
        mutable_file::unwrap_for_private_key(&staged_envelope, source_private_key)
            .map_err(|_| CryptoError::DecryptionFailed)?;
    mutable_file::verify_header(&staged_root_key, &staged_envelope)?;
    file::decrypt_payload_frames(
        output.as_file_mut(),
        &mut io::sink(),
        staged_envelope.plaintext_len,
        &staged_envelope.payload_base_nonce,
        &staged_root_key,
        &staged_envelope.payload_binding,
        V3SuiteId::XChaCha20Poly1305,
        None,
    )?;
    output.as_file().sync_all()?;
    mutable_file::persist(output, output_path, replace_existing)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::*;
    use crate::crypto::keys::generate_keypair;

    fn payload_bytes(path: &Path) -> Vec<u8> {
        let bytes = fs::read(path).unwrap();
        let envelope_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        bytes[4 + envelope_len..].to_vec()
    }

    #[test]
    fn converts_single_recipient_without_changing_source_or_frames() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let converted = directory.path().join("converted.lvau");
        let decrypted_a3 = directory.path().join("a3.out");
        let decrypted_a4 = directory.path().join("a4.out");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"A3 payload bytes stay unchanged").unwrap();
        hpke_file::encrypt_file_keypairs(
            &plaintext,
            &source,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();
        let source_bytes = fs::read(&source).unwrap();

        convert_a3_to_a4(&source, &converted, &private, &[], false).unwrap();

        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert_eq!(payload_bytes(&source), payload_bytes(&converted));
        hpke_file::decrypt_file_keypair(&source, &decrypted_a3, &private, false, None).unwrap();
        mutable_file::decrypt_file_keypair(&converted, &decrypted_a4, &private, false, None)
            .unwrap();
        assert_eq!(
            fs::read(decrypted_a3).unwrap(),
            fs::read(&plaintext).unwrap()
        );
        assert_eq!(
            fs::read(decrypted_a4).unwrap(),
            fs::read(plaintext).unwrap()
        );
    }

    #[test]
    fn converts_multiple_recipients_and_retains_explicit_extra() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let converted = directory.path().join("converted.lvau");
        let (private_a, public_a) = generate_keypair();
        let (private_b, public_b) = generate_keypair();
        let (private_extra, public_extra) = generate_keypair();
        fs::write(&plaintext, b"all retained recipients decrypt").unwrap();
        hpke_file::encrypt_file_keypairs(&plaintext, &source, &[public_a, public_b], false, None)
            .unwrap();
        let retained_a = HybridPublicKey {
            x25519: X25519PublicKey::from(&private_a.x25519),
            mlkem: private_a.mlkem.encapsulation_key().clone(),
        };
        let (_, mut retained_b) = generate_keypair();
        retained_b.x25519 = X25519PublicKey::from(&private_b.x25519);

        convert_a3_to_a4(
            &source,
            &converted,
            &private_a,
            &[retained_a, retained_b, public_extra],
            false,
        )
        .unwrap();

        hpke_file::verify_file_keypair(&source, &private_a, None).unwrap();
        hpke_file::verify_file_keypair(&source, &private_b, None).unwrap();
        for private in [&private_a, &private_b, &private_extra] {
            mutable_file::verify_file_keypair(&converted, private, None).unwrap();
        }
    }

    #[test]
    fn rejects_missing_original_recipient_and_wrong_key() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let missing = directory.path().join("missing.lvau");
        let wrong = directory.path().join("wrong.lvau");
        let (private_a, public_a) = generate_keypair();
        let (_, public_b) = generate_keypair();
        let (wrong_private, _) = generate_keypair();
        fs::write(&plaintext, b"recipient coverage").unwrap();
        hpke_file::encrypt_file_keypairs(&plaintext, &source, &[public_a, public_b], false, None)
            .unwrap();

        assert!(matches!(
            convert_a3_to_a4(&source, &missing, &private_a, &[], false),
            Err(CryptoError::Validation(
                "destination recipients do not cover every A3 recipient"
            ))
        ));
        assert!(matches!(
            convert_a3_to_a4(&source, &wrong, &wrong_private, &[], false),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(!missing.exists());
        assert!(!wrong.exists());
    }

    #[test]
    fn rejects_tampered_and_truncated_frames_without_output() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"authenticated before conversion").unwrap();
        hpke_file::encrypt_file_keypairs(
            &plaintext,
            &source,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();
        let source_bytes = fs::read(&source).unwrap();

        let mut tampered_bytes = source_bytes.clone();
        *tampered_bytes.last_mut().unwrap() ^= 1;
        let tampered = directory.path().join("tampered.lvau");
        fs::write(&tampered, tampered_bytes).unwrap();
        let tampered_output = directory.path().join("tampered-output.lvau");
        assert!(convert_a3_to_a4(&tampered, &tampered_output, &private, &[], false).is_err());
        assert!(!tampered_output.exists());

        let truncated = directory.path().join("truncated.lvau");
        fs::write(&truncated, &source_bytes[..source_bytes.len() - 1]).unwrap();
        let truncated_output = directory.path().join("truncated-output.lvau");
        assert!(convert_a3_to_a4(&truncated, &truncated_output, &private, &[], false).is_err());
        assert!(!truncated_output.exists());
        assert_eq!(fs::read(source).unwrap(), source_bytes);
    }

    #[test]
    fn existing_output_is_not_clobbered_and_same_path_is_refused() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let output = directory.path().join("existing.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"no clobber").unwrap();
        hpke_file::encrypt_file_keypairs(
            &plaintext,
            &source,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();
        fs::write(&output, b"keep me").unwrap();
        let source_bytes = fs::read(&source).unwrap();

        assert!(matches!(
            convert_a3_to_a4(&source, &output, &private, &[], false),
            Err(CryptoError::OutputExists)
        ));
        assert_eq!(fs::read(output).unwrap(), b"keep me");
        let equivalent_source = directory.path().join(".").join("source.lvau");
        assert!(matches!(
            convert_a3_to_a4(&source, &equivalent_source, &private, &[], true),
            Err(CryptoError::Validation(
                "A3-to-A4 conversion requires distinct input and output paths"
            ))
        ));
        assert_eq!(fs::read(source).unwrap(), source_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_hardlink_output_alias_without_changing_source() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let output_alias = directory.path().join("output-alias.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"source hardlink stays readable").unwrap();
        hpke_file::encrypt_file_keypairs(
            &plaintext,
            &source,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&source).unwrap();
        fs::hard_link(&source, &output_alias).unwrap();

        assert!(matches!(
            convert_a3_to_a4(&source, &output_alias, &private, &[], true),
            Err(CryptoError::Validation(
                "A3-to-A4 conversion requires distinct input and output paths"
            ))
        ));

        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&output_alias).unwrap(), original);
        assert!(same_file::is_same_file(&source, &output_alias).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_output_alias_without_touching_source() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let output_alias = directory.path().join("output-alias.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"source symlink stays readable").unwrap();
        hpke_file::encrypt_file_keypairs(
            &plaintext,
            &source,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&source).unwrap();
        std::os::unix::fs::symlink(&source, &output_alias).unwrap();

        assert!(matches!(
            convert_a3_to_a4(&source, &output_alias, &private, &[], true),
            Err(CryptoError::Validation(
                "A3-to-A4 conversion requires distinct input and output paths"
            ))
        ));
        assert_eq!(fs::read(&source).unwrap(), original);
        assert!(fs::symlink_metadata(output_alias)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn rejects_duplicate_and_noncanonical_destination_keys() {
        let directory = tempdir().unwrap();
        let plaintext = directory.path().join("plaintext");
        let source = directory.path().join("source.lvau");
        let output = directory.path().join("output.lvau");
        let (private, public) = generate_keypair();
        fs::write(&plaintext, b"destination validation").unwrap();
        hpke_file::encrypt_file_keypairs(
            &plaintext,
            &source,
            std::slice::from_ref(&public),
            false,
            None,
        )
        .unwrap();

        let (_, duplicate) = generate_keypair();
        let (_, mut duplicate_again) = generate_keypair();
        duplicate_again.x25519 = duplicate.x25519;
        assert!(matches!(
            convert_a3_to_a4(
                &source,
                &output,
                &private,
                &[duplicate, duplicate_again],
                false,
            ),
            Err(CryptoError::Validation("Duplicate v3 X25519 recipient"))
        ));
        let (_, mut invalid) = generate_keypair();
        invalid.x25519 = X25519PublicKey::from([0xff; 32]);
        assert!(matches!(
            convert_a3_to_a4(&source, &output, &private, &[invalid], false),
            Err(CryptoError::Validation(
                "Recipient X25519 public key is not canonical"
            ))
        ));

        let too_many = (0..V3_MUTABLE_MAX_RECIPIENTS)
            .map(|_| generate_keypair().1)
            .collect::<Vec<_>>();
        assert!(matches!(
            convert_a3_to_a4(&source, &output, &private, &too_many, false),
            Err(CryptoError::Validation(
                "v3 recipient slot count is invalid"
            ))
        ));
        assert!(!output.exists());
    }
}

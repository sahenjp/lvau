use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use hpke::aead::ChaCha20Poly1305 as HpkeAead;
use hpke::kdf::HkdfSha256 as HpkeKdf;
use hpke::kem::X25519HkdfSha256 as HpkeKem;
use hpke::{
    single_shot_open, single_shot_seal, Deserializable, Kem as HpkeKemTrait, OpModeR, OpModeS,
    Serializable,
};
use lvau_protocol::envelope_v3::{
    V3HpkeEnvelope, V3HpkePayloadCore, V3HpkeRecipient, V3_HPKE_ENVELOPE_REVISION,
    V3_HPKE_MAX_ENVELOPE_SIZE, V3_HPKE_MAX_RECIPIENTS,
    V3_HPKE_RECIPIENT_SUITE_X25519_HKDF_SHA256_CHACHA20POLY1305, V3_MAGIC,
    V3_SUITE_XCHACHA20_POLY1305, V3_VERSION,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use super::file::V3FileRevision;
use super::file::{decrypt_payload_frames, encrypt_payload_frames, envelope_commitment};
use super::V3SuiteId;
use crate::crypto::keys::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::output::persist_temp_path;
use crate::crypto::CryptoError;

const RECIPIENT_SUITE_ID: u8 = V3_HPKE_RECIPIENT_SUITE_X25519_HKDF_SHA256_CHACHA20POLY1305;
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0003;
const KEY_ID_DOMAIN: &[u8] = b"Lvau v3 recipient key ID\0";
const CORE_DOMAIN: &[u8] = b"Lvau v3 HPKE payload core\0";
const HPKE_INFO_DOMAIN: &[u8] = b"Lvau v3 HPKE root-wrap info\0";
const HPKE_AAD_DOMAIN: &[u8] = b"Lvau v3 HPKE root-wrap AAD\0";
const ROOT_KEY_LEN: usize = 32;
const HPKE_CIPHERTEXT_LEN: usize = ROOT_KEY_LEN + 16;

type HpkePublicKey = <HpkeKem as HpkeKemTrait>::PublicKey;
type HpkePrivateKey = <HpkeKem as HpkeKemTrait>::PrivateKey;
type HpkeEncappedKey = <HpkeKem as HpkeKemTrait>::EncappedKey;

#[derive(Debug, Clone)]
pub struct V3HpkeFileInfo {
    pub envelope: V3HpkeEnvelope,
}

pub(super) fn is_canonical_x25519(bytes: &[u8; 32]) -> bool {
    if bytes[31] & 0x80 != 0 {
        return false;
    }
    for index in (0..32).rev() {
        let modulus_byte = match index {
            0 => 0xed,
            31 => 0x7f,
            _ => 0xff,
        };
        match bytes[index].cmp(&modulus_byte) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

pub(super) fn recipient_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_ID_DOMAIN);
    hash.update([RECIPIENT_SUITE_ID]);
    hash.update(KEM_ID.to_be_bytes());
    hash.update(KDF_ID.to_be_bytes());
    hash.update(AEAD_ID.to_be_bytes());
    hash.update(public_key);
    hash.finalize().into()
}

fn core_commitment(envelope: &V3HpkeEnvelope) -> Result<[u8; 32], CryptoError> {
    let core = V3HpkePayloadCore {
        magic: &envelope.magic,
        version: envelope.version,
        envelope_revision: envelope.envelope_revision,
        payload_suite_id: envelope.payload_suite_id,
        payload_base_nonce: &envelope.payload_base_nonce,
        plaintext_len: envelope.plaintext_len,
    };
    let mut hash = Sha256::new();
    hash.update(CORE_DOMAIN);
    hash.update(postcard::to_allocvec(&core)?);
    Ok(hash.finalize().into())
}

fn hpke_context(core: &[u8; 32], key_id: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut info = Vec::with_capacity(HPKE_INFO_DOMAIN.len() + 71);
    info.extend_from_slice(HPKE_INFO_DOMAIN);
    info.extend_from_slice(core);
    info.push(RECIPIENT_SUITE_ID);
    info.extend_from_slice(&KEM_ID.to_be_bytes());
    info.extend_from_slice(&KDF_ID.to_be_bytes());
    info.extend_from_slice(&AEAD_ID.to_be_bytes());
    info.extend_from_slice(key_id);

    let mut aad = Vec::with_capacity(HPKE_AAD_DOMAIN.len() + 71);
    aad.extend_from_slice(HPKE_AAD_DOMAIN);
    aad.extend_from_slice(core);
    aad.push(RECIPIENT_SUITE_ID);
    aad.extend_from_slice(&KEM_ID.to_be_bytes());
    aad.extend_from_slice(&KDF_ID.to_be_bytes());
    aad.extend_from_slice(&AEAD_ID.to_be_bytes());
    aad.extend_from_slice(key_id);
    (info, aad)
}

pub(super) fn validate_envelope(envelope: &V3HpkeEnvelope) -> Result<(), CryptoError> {
    if envelope.magic != V3_MAGIC
        || envelope.version != V3_VERSION
        || envelope.envelope_revision != V3_HPKE_ENVELOPE_REVISION
    {
        return Err(CryptoError::Validation(
            "Unsupported v3 HPKE envelope revision",
        ));
    }
    if envelope.payload_suite_id != V3_SUITE_XCHACHA20_POLY1305 {
        return Err(CryptoError::Validation("Unsupported v3 payload suite"));
    }
    if envelope.recipients.is_empty() || envelope.recipients.len() > V3_HPKE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 HPKE recipient count is invalid",
        ));
    }

    let mut previous = None;
    for recipient in &envelope.recipients {
        if recipient.recipient_suite_id != RECIPIENT_SUITE_ID
            || !is_canonical_x25519(&recipient.enc)
        {
            return Err(CryptoError::Validation("Invalid v3 HPKE recipient slot"));
        }
        let current = (recipient.recipient_suite_id, recipient.key_id);
        if previous.is_some_and(|previous| current <= previous) {
            return Err(CryptoError::Validation(
                "v3 HPKE recipients are duplicated or not canonically ordered",
            ));
        }
        previous = Some(current);
    }
    Ok(())
}

fn encode_envelope(envelope: &V3HpkeEnvelope) -> Result<Vec<u8>, CryptoError> {
    validate_envelope(envelope)?;
    let bytes = postcard::to_allocvec(envelope)?;
    if bytes.is_empty() || bytes.len() > V3_HPKE_MAX_ENVELOPE_SIZE {
        return Err(CryptoError::Validation("v3 HPKE envelope size is invalid"));
    }
    Ok(bytes)
}

pub(super) fn read_envelope(
    reader: &mut dyn Read,
) -> Result<(V3HpkeEnvelope, Vec<u8>), CryptoError> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if !(6..=V3_HPKE_MAX_ENVELOPE_SIZE).contains(&length) {
        return Err(CryptoError::Validation("v3 HPKE envelope size is invalid"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let (envelope, trailing) = postcard::take_from_bytes::<V3HpkeEnvelope>(&bytes)?;
    if !trailing.is_empty() || postcard::to_allocvec(&envelope)? != bytes {
        return Err(CryptoError::Validation(
            "v3 HPKE envelope encoding is not canonical",
        ));
    }
    validate_envelope(&envelope)?;
    Ok((envelope, bytes))
}

fn import_public_key(bytes: &[u8; 32]) -> Result<HpkePublicKey, CryptoError> {
    if !is_canonical_x25519(bytes) {
        return Err(CryptoError::Validation(
            "Recipient X25519 public key is not canonical",
        ));
    }
    HpkePublicKey::from_bytes(bytes)
        .map_err(|_| CryptoError::Validation("Invalid recipient X25519 public key"))
}

fn wrap_root_key(
    root_key: &[u8; 32],
    public_key_bytes: &[u8; 32],
    core: &[u8; 32],
    key_id: &[u8; 32],
) -> Result<V3HpkeRecipient, CryptoError> {
    let public_key = import_public_key(public_key_bytes)?;
    let (info, aad) = hpke_context(core, key_id);
    let (enc, ciphertext) = single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        &public_key,
        &info,
        root_key,
        &aad,
    )
    .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut enc_bytes = [0; 32];
    enc.write_exact(&mut enc_bytes);
    let encrypted_file_root_key: [u8; HPKE_CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(V3HpkeRecipient {
        recipient_suite_id: RECIPIENT_SUITE_ID,
        key_id: *key_id,
        enc: enc_bytes,
        encrypted_file_root_key,
    })
}

fn unwrap_root_key(
    private_key: &HybridPrivateKey,
    recipient: &V3HpkeRecipient,
    core: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if !is_canonical_x25519(&recipient.enc) {
        return Err(CryptoError::DecryptionFailed);
    }
    let private_bytes = Zeroizing::new(private_key.x25519.to_bytes());
    let hpke_private =
        HpkePrivateKey::from_bytes(&*private_bytes).map_err(|_| CryptoError::DecryptionFailed)?;
    let hpke_public = HpkeKem::sk_to_pk(&hpke_private);
    let mut public_bytes = [0; 32];
    hpke_public.write_exact(&mut public_bytes);
    if !is_canonical_x25519(&public_bytes) || recipient_key_id(&public_bytes) != recipient.key_id {
        return Err(CryptoError::DecryptionFailed);
    }
    let enc =
        HpkeEncappedKey::from_bytes(&recipient.enc).map_err(|_| CryptoError::DecryptionFailed)?;
    let (info, aad) = hpke_context(core, &recipient.key_id);
    let plaintext = Zeroizing::new(
        single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &hpke_private,
            &enc,
            &info,
            &recipient.encrypted_file_root_key,
            &aad,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    if plaintext.len() != 32 {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut root_key = Zeroizing::new([0; 32]);
    root_key.copy_from_slice(&plaintext);
    Ok(root_key)
}

fn persist(
    output: NamedTempFile,
    output_path: &Path,
    replace_existing: bool,
) -> Result<(), CryptoError> {
    persist_temp_path(output.into_temp_path(), output_path, replace_existing).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CryptoError::OutputExists
        } else {
            CryptoError::Io(error)
        }
    })
}

pub fn encrypt_file_keypairs(
    input_path: &Path,
    output_path: &Path,
    recipient_public_keys: &[HybridPublicKey],
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    if recipient_public_keys.is_empty() || recipient_public_keys.len() > V3_HPKE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 HPKE recipient count is invalid",
        ));
    }

    let mut recipients = Vec::with_capacity(recipient_public_keys.len());
    for recipient in recipient_public_keys {
        let public_key = recipient.x25519.to_bytes();
        if !is_canonical_x25519(&public_key) {
            return Err(CryptoError::Validation(
                "Recipient X25519 public key is not canonical",
            ));
        }
        recipients.push((recipient_key_id(&public_key), public_key));
    }
    recipients.sort_by_key(|(key_id, _)| *key_id);
    if recipients.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CryptoError::Validation("Duplicate v3 HPKE recipient"));
    }

    let mut input = File::open(input_path)?;
    let plaintext_len = input.metadata()?.len();
    let mut rng = OsRng;
    let mut root_key = Zeroizing::new([0; 32]);
    rng.fill_bytes(&mut *root_key);
    let mut payload_base_nonce = [0; 24];
    rng.fill_bytes(&mut payload_base_nonce);
    let mut envelope = V3HpkeEnvelope {
        magic: V3_MAGIC,
        version: V3_VERSION,
        envelope_revision: V3_HPKE_ENVELOPE_REVISION,
        payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
        payload_base_nonce,
        plaintext_len,
        recipients: Vec::with_capacity(recipients.len()),
    };
    let core = core_commitment(&envelope)?;
    for (key_id, public_key) in recipients {
        envelope
            .recipients
            .push(wrap_root_key(&root_key, &public_key, &core, &key_id)?);
    }
    envelope
        .recipients
        .sort_by_key(|recipient| (recipient.recipient_suite_id, recipient.key_id));
    let envelope_bytes = encode_envelope(&envelope)?;
    let commitment = envelope_commitment(&root_key, V3SuiteId::XChaCha20Poly1305, &envelope_bytes)?;

    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut output = NamedTempFile::new_in(parent)?;
    output.write_all(&(envelope_bytes.len() as u32).to_le_bytes())?;
    output.write_all(&envelope_bytes)?;
    encrypt_payload_frames(
        &mut input,
        &mut output,
        plaintext_len,
        &envelope.payload_base_nonce,
        &root_key,
        &commitment,
        V3SuiteId::XChaCha20Poly1305,
        progress,
    )?;
    output.as_file().sync_all()?;
    persist(output, output_path, replace_existing)
}

pub(super) fn unwrap_for_private_key(
    envelope: &V3HpkeEnvelope,
    private_key: &HybridPrivateKey,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let private_bytes = Zeroizing::new(private_key.x25519.to_bytes());
    let hpke_private =
        HpkePrivateKey::from_bytes(&*private_bytes).map_err(|_| CryptoError::DecryptionFailed)?;
    let hpke_public = HpkeKem::sk_to_pk(&hpke_private);
    let mut public_bytes = [0; 32];
    hpke_public.write_exact(&mut public_bytes);
    if !is_canonical_x25519(&public_bytes) {
        return Err(CryptoError::DecryptionFailed);
    }
    let key_id = recipient_key_id(&public_bytes);
    let recipient = envelope
        .recipients
        .iter()
        .find(|recipient| {
            recipient.recipient_suite_id == RECIPIENT_SUITE_ID && recipient.key_id == key_id
        })
        .ok_or(CryptoError::DecryptionFailed)?;
    let core = core_commitment(envelope)?;
    unwrap_root_key(private_key, recipient, &core)
}

pub fn decrypt_file_keypair(
    input_path: &Path,
    output_path: &Path,
    private_key: &HybridPrivateKey,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let mut input = File::open(input_path)?;
    let (envelope, envelope_bytes) = read_envelope(&mut input)?;
    let root_key = unwrap_for_private_key(&envelope, private_key)?;
    let commitment = envelope_commitment(&root_key, V3SuiteId::XChaCha20Poly1305, &envelope_bytes)?;
    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut output = NamedTempFile::new_in(parent)?;
    decrypt_payload_frames(
        &mut input,
        &mut output,
        envelope.plaintext_len,
        &envelope.payload_base_nonce,
        &root_key,
        &commitment,
        V3SuiteId::XChaCha20Poly1305,
        progress,
    )?;
    output.as_file().sync_all()?;
    persist(output, output_path, replace_existing)
}

pub fn verify_file_keypair(
    input_path: &Path,
    private_key: &HybridPrivateKey,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let mut input = File::open(input_path)?;
    let (envelope, envelope_bytes) = read_envelope(&mut input)?;
    let root_key = unwrap_for_private_key(&envelope, private_key)?;
    let commitment = envelope_commitment(&root_key, V3SuiteId::XChaCha20Poly1305, &envelope_bytes)?;
    decrypt_payload_frames(
        &mut input,
        &mut io::sink(),
        envelope.plaintext_len,
        &envelope.payload_base_nonce,
        &root_key,
        &commitment,
        V3SuiteId::XChaCha20Poly1305,
        progress,
    )
}

pub fn inspect_file(input_path: &Path) -> Result<V3HpkeFileInfo, CryptoError> {
    let mut input = File::open(input_path)?;
    let (envelope, _) = read_envelope(&mut input)?;
    Ok(V3HpkeFileInfo { envelope })
}

pub fn is_v3_hpke_file(input_path: &Path) -> Result<bool, CryptoError> {
    Ok(super::file::file_revision(input_path)? == V3FileRevision::HpkeRecipients)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_keypair;
    use std::fs;
    use tempfile::tempdir;
    use x25519_dalek::PublicKey as X25519PublicKey;

    fn hex(bytes: &[u8]) -> Vec<u8> {
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn opens_rfc_9180_base_mode_x25519_chacha_vector() {
        let private = HpkePrivateKey::from_bytes(&hex(
            b"8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        ))
        .unwrap();
        let enc = HpkeEncappedKey::from_bytes(&hex(
            b"1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        ))
        .unwrap();
        let plaintext = single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &private,
            &enc,
            &hex(b"4f6465206f6e2061204772656369616e2055726e"),
            &hex(b"1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
            &hex(b"436f756e742d30"),
        )
        .unwrap();
        assert_eq!(plaintext, b"Beauty is truth, truth beauty");
    }

    #[test]
    fn multi_recipient_roundtrip_selects_the_matching_hpke_key() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted.lvau");
        let output_a = dir.path().join("output-a");
        let output_b = dir.path().join("output-b");
        let wrong_output = dir.path().join("wrong-output");
        fs::write(&input, b"multiple HPKE recipients").unwrap();
        let (private_a, public_a) = generate_keypair();
        let (private_b, public_b) = generate_keypair();
        let (wrong_private, _) = generate_keypair();

        encrypt_file_keypairs(&input, &encrypted, &[public_a, public_b], false, None).unwrap();
        let info = inspect_file(&encrypted).unwrap();
        assert_eq!(info.envelope.recipients.len(), 2);
        decrypt_file_keypair(&encrypted, &output_a, &private_a, false, None).unwrap();
        decrypt_file_keypair(&encrypted, &output_b, &private_b, false, None).unwrap();
        assert_eq!(fs::read(&output_a).unwrap(), fs::read(&input).unwrap());
        assert_eq!(fs::read(&output_b).unwrap(), fs::read(&input).unwrap());
        assert!(
            decrypt_file_keypair(&encrypted, &wrong_output, &wrong_private, false, None).is_err()
        );
        assert!(!wrong_output.exists());
    }

    #[test]
    fn hpke_envelope_and_payload_tampering_fail_without_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted.lvau");
        let output = dir.path().join("output");
        fs::write(&input, b"authenticated HPKE payload").unwrap();
        let (private, public) = generate_keypair();
        encrypt_file_keypairs(&input, &encrypted, &[public], false, None).unwrap();
        let original = fs::read(&encrypted).unwrap();
        let envelope_len = u32::from_le_bytes(original[..4].try_into().unwrap()) as usize;
        let (mut envelope, trailing) =
            postcard::take_from_bytes::<V3HpkeEnvelope>(&original[4..4 + envelope_len]).unwrap();
        assert!(trailing.is_empty());
        envelope.recipients[0].encrypted_file_root_key[0] ^= 1;
        let encoded = postcard::to_allocvec(&envelope).unwrap();
        let mut damaged = (encoded.len() as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&encoded);
        damaged.extend_from_slice(&original[4 + envelope_len..]);
        fs::write(&encrypted, damaged).unwrap();
        assert!(decrypt_file_keypair(&encrypted, &output, &private, false, None).is_err());
        assert!(!output.exists());

        let mut damaged = original.clone();
        damaged[4 + envelope_len] ^= 1;
        fs::write(&encrypted, &damaged).unwrap();
        assert!(decrypt_file_keypair(&encrypted, &output, &private, false, None).is_err());
        assert!(verify_file_keypair(&encrypted, &private, None).is_err());
        assert!(!output.exists());

        fs::write(&output, b"preserve existing output").unwrap();
        assert!(decrypt_file_keypair(&encrypted, &output, &private, true, None).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve existing output");

        let mut truncated = original.clone();
        truncated.pop();
        fs::write(&encrypted, truncated).unwrap();
        assert!(decrypt_file_keypair(&encrypted, &output, &private, true, None).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve existing output");

        let mut trailing = original;
        trailing.push(0);
        fs::write(&encrypted, trailing).unwrap();
        assert!(verify_file_keypair(&encrypted, &private, None).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve existing output");
    }

    #[test]
    fn zero_or_sixty_five_recipient_slots_are_rejected() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let path = dir.path().join("invalid.lvau");
        fs::write(&input, b"bounded recipients").unwrap();
        let (private, _public) = generate_keypair();
        assert!(encrypt_file_keypairs(&input, &path, &[], false, None).is_err());
        assert!(!path.exists());

        let (_, key) = generate_keypair();
        let public_bytes = key.x25519.to_bytes();
        let id = recipient_key_id(&public_bytes);
        let slot = V3HpkeRecipient {
            recipient_suite_id: RECIPIENT_SUITE_ID,
            key_id: id,
            enc: [1; 32],
            encrypted_file_root_key: [0; 48],
        };
        let mut envelope = V3HpkeEnvelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            envelope_revision: V3_HPKE_ENVELOPE_REVISION,
            payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
            payload_base_nonce: [1; 24],
            plaintext_len: 0,
            recipients: vec![slot; V3_HPKE_MAX_RECIPIENTS + 1],
        };
        envelope
            .recipients
            .sort_by_key(|recipient| recipient.key_id);
        let encoded = postcard::to_allocvec(&envelope).unwrap();
        let mut bytes = (encoded.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&encoded);
        fs::write(&path, bytes).unwrap();
        assert!(inspect_file(&path).is_err());
        assert!(
            decrypt_file_keypair(&path, &dir.path().join("out"), &private, false, None).is_err()
        );
    }

    #[test]
    fn low_order_and_noncanonical_x25519_encodings_fail_closed() {
        assert!(is_canonical_x25519(&[0; 32]));
        assert!(!is_canonical_x25519(&[0xff; 32]));
        assert!(HpkePublicKey::from_bytes(&[0xff; 32]).is_ok());

        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let output = dir.path().join("output.lvau");
        fs::write(&input, b"low-order key").unwrap();
        let (_, mut public) = generate_keypair();
        public.x25519 = X25519PublicKey::from([0; 32]);
        assert!(encrypt_file_keypairs(&input, &output, &[public], false, None).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn empty_payload_roundtrips_for_hpke_recipient() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("empty");
        let encrypted = dir.path().join("empty.lvau");
        let output = dir.path().join("output");
        fs::write(&input, []).unwrap();
        let (private, public) = generate_keypair();

        encrypt_file_keypairs(&input, &encrypted, &[public], false, None).unwrap();
        decrypt_file_keypair(&encrypted, &output, &private, false, None).unwrap();
        assert!(fs::read(output).unwrap().is_empty());
    }

    #[test]
    fn unknown_v3_revision_fails_before_legacy_decoder_fallback() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("unknown-revision.lvau");
        let mut bytes = 6u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&V3_MAGIC);
        bytes.push(V3_VERSION as u8);
        bytes.push(V3_HPKE_ENVELOPE_REVISION ^ 1);
        fs::write(&input, bytes).unwrap();

        assert!(crate::crypto::suite::v3::file::is_v3_file(&input).unwrap());
        assert!(crate::crypto::suite::v3::file::file_revision(&input).is_err());
    }
}

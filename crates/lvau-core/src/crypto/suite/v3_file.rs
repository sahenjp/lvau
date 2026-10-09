use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use lvau_protocol::envelope::SecurityProfile;
use lvau_protocol::envelope_v3::{
    V3Envelope, V3RootWrapAad, V3_HPKE_ENVELOPE_REVISION, V3_HPKE_MAX_ENVELOPE_SIZE,
    V3_KDF_ARGON2ID_V13, V3_MAGIC, V3_MAX_ENVELOPE_SIZE, V3_MUTABLE_ENVELOPE_REVISION,
    V3_MUTABLE_MAX_ENVELOPE_SIZE, V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305,
    V3_SUITE_XCHACHA20_POLY1305, V3_VERSION,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use tempfile::{tempdir_in, NamedTempFile};
use zeroize::Zeroizing;

use crate::crypto::output::persist_temp_path;
use crate::crypto::suite::v3::{
    decrypt_layered_chunk, decrypt_xchacha_chunk, derive_subkey, encrypt_layered_chunk,
    encrypt_xchacha_chunk, V3ChunkDescriptor, V3KeyPurpose, V3_MAX_CHUNK_PLAINTEXT_LEN,
};
use crate::crypto::suite::V3SuiteId;
use crate::crypto::CryptoError;

const WRAP_KEY_DOMAIN: &[u8] = b"Lvau v3 password root wrapping\0";
const WRAP_AAD_DOMAIN: &[u8] = b"Lvau v3 password root AAD\0";
const COMMITMENT_DOMAIN: &[u8] = b"Lvau v3 envelope commitment\0";
const SINGLE_SUITE_NAME: &[u8] = b"LV3-XC20P";
const LAYERED_SUITE_NAME: &[u8] = b"LV3-AESGCMSIV-XC20P";
const SINGLE_TAG_LEN: usize = 16;
const LAYERED_TAG_LEN: usize = 32;

pub struct V3FileInfo {
    pub envelope: V3Envelope,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

pub(super) fn profile_id(profile: &SecurityProfile) -> u8 {
    match profile {
        SecurityProfile::Fast => 0,
        SecurityProfile::Balanced => 1,
        SecurityProfile::Archive => 2,
        SecurityProfile::Paranoid => 3,
        SecurityProfile::Extreme => 4,
    }
}

pub(super) fn profile_costs(id: u8) -> Result<(u32, u32, u32), CryptoError> {
    match id {
        0 => Ok((16_384, 1, 1)),
        1 => Ok((65_536, 2, 1)),
        2 => Ok((262_144, 3, 2)),
        3 | 4 => Ok((1_048_576, 4, 4)),
        _ => Err(CryptoError::UnsupportedProfile),
    }
}

pub(super) fn validate_envelope(envelope: &V3Envelope) -> Result<(u32, u32, u32), CryptoError> {
    if envelope.magic != V3_MAGIC {
        return Err(CryptoError::Validation(
            "Invalid magic bytes, not a Lvau file",
        ));
    }
    if envelope.version != V3_VERSION {
        return Err(CryptoError::Validation("Unsupported format version"));
    }
    suite_from_id(envelope.suite_id)?;
    if envelope.kdf_id != V3_KDF_ARGON2ID_V13 {
        return Err(CryptoError::Validation("Unsupported v3 password KDF"));
    }
    profile_costs(envelope.profile_id)
}

/// Resolve a legacy password-v3 payload suite from its wire identifier.
///
/// Only suites that were actually written are accepted; unknown identifiers
/// fail closed before any KDF work.
pub fn suite_from_id(suite_id: u8) -> Result<V3SuiteId, CryptoError> {
    match suite_id {
        V3_SUITE_XCHACHA20_POLY1305 => Ok(V3SuiteId::XChaCha20Poly1305),
        V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305 => Ok(V3SuiteId::Aes256GcmSivXChaCha20Poly1305),
        _ => Err(CryptoError::Validation("Unsupported v3 payload suite")),
    }
}

pub(super) fn suite_wire_id(suite: V3SuiteId) -> u8 {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => V3_SUITE_XCHACHA20_POLY1305,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305,
    }
}

fn suite_wrap_name(suite: V3SuiteId) -> &'static [u8] {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => SINGLE_SUITE_NAME,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => LAYERED_SUITE_NAME,
    }
}

/// Human-readable wire name for a validated legacy password-v3 suite.
pub fn payload_suite_name(suite: V3SuiteId) -> &'static str {
    crate::crypto::suite::v3::suite_wire_name(suite)
}

fn frame_tag_len(suite: V3SuiteId) -> usize {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => SINGLE_TAG_LEN,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => LAYERED_TAG_LEN,
    }
}

pub(super) fn derive_master_key(
    password: &SecretString,
    salt: &[u8; 16],
    costs: (u32, u32, u32),
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(costs.0, costs.1, costs.2, Some(32))
        .map_err(|_| CryptoError::UnsupportedProfile)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut *key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(key)
}

pub(super) fn derive_wrapping_key(
    master_key: &[u8; 32],
    suite: V3SuiteId,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(WRAP_KEY_DOMAIN), master_key);
    let mut key = Zeroizing::new([0; 32]);
    hk.expand(suite_wrap_name(suite), &mut *key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(key)
}

fn wrap_aad(envelope: &V3Envelope) -> Result<Vec<u8>, CryptoError> {
    let fields = V3RootWrapAad {
        magic: &envelope.magic,
        version: envelope.version,
        suite_id: envelope.suite_id,
        profile_id: envelope.profile_id,
        kdf_id: envelope.kdf_id,
        salt: &envelope.salt,
        wrapping_nonce: &envelope.wrapping_nonce,
        payload_base_nonce: &envelope.payload_base_nonce,
        plaintext_len: envelope.plaintext_len,
    };
    let mut aad = Vec::from(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(&postcard::to_allocvec(&fields)?);
    Ok(aad)
}

pub(super) fn envelope_commitment(
    root_key: &[u8; 32],
    suite: V3SuiteId,
    envelope_bytes: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let subkey = derive_subkey(root_key, suite, V3KeyPurpose::EnvelopeCommitment)?;
    let hk = Hkdf::<Sha256>::new(Some(COMMITMENT_DOMAIN), &*subkey);
    let mut commitment = [0; 32];
    hk.expand(envelope_bytes, &mut commitment)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(commitment)
}

fn encode_envelope(envelope: &V3Envelope) -> Result<Vec<u8>, CryptoError> {
    let bytes = postcard::to_allocvec(envelope)?;
    if bytes.is_empty() || bytes.len() > V3_MAX_ENVELOPE_SIZE {
        return Err(CryptoError::Validation("v3 envelope size is invalid"));
    }
    Ok(bytes)
}

pub(super) fn read_envelope(reader: &mut dyn Read) -> Result<(V3Envelope, Vec<u8>), CryptoError> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > V3_MAX_ENVELOPE_SIZE {
        return Err(CryptoError::Validation("v3 envelope size is invalid"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let (envelope, trailing) = postcard::take_from_bytes::<V3Envelope>(&bytes)?;
    if !trailing.is_empty() {
        return Err(CryptoError::Validation("v3 envelope has trailing bytes"));
    }
    validate_envelope(&envelope)?;
    Ok((envelope, bytes))
}

pub(super) fn unwrap_root_key(
    envelope: &V3Envelope,
    password: &SecretString,
    costs: (u32, u32, u32),
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let master_key = derive_master_key(password, &envelope.salt, costs)?;
    let wrapping_key = derive_wrapping_key(&master_key, suite_from_id(envelope.suite_id)?)?;
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(envelope.wrapping_nonce),
                Payload {
                    msg: &envelope.encrypted_file_root_key,
                    aad: &wrap_aad(envelope)?,
                },
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

fn frame_count(plaintext_len: u64) -> Result<u64, CryptoError> {
    if plaintext_len == 0 {
        return Ok(1);
    }
    plaintext_len
        .checked_add(V3_MAX_CHUNK_PLAINTEXT_LEN as u64 - 1)
        .map(|length| length / V3_MAX_CHUNK_PLAINTEXT_LEN as u64)
        .ok_or(CryptoError::Validation("v3 plaintext length overflow"))
}

fn frame_plaintext_len(total: u64, index: u64, count: u64) -> usize {
    if total == 0 {
        0
    } else if index + 1 == count {
        (total - index * V3_MAX_CHUNK_PLAINTEXT_LEN as u64) as usize
    } else {
        V3_MAX_CHUNK_PLAINTEXT_LEN
    }
}

fn read_frame(reader: &mut dyn Read, length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => CryptoError::DecryptionFailed,
            _ => CryptoError::Io(error),
        })?;
    Ok(bytes)
}

fn decrypt_frame(
    suite: V3SuiteId,
    root_key: &[u8; 32],
    payload_base_nonce: &[u8; 24],
    commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => decrypt_xchacha_chunk(
            root_key,
            payload_base_nonce,
            commitment,
            descriptor,
            ciphertext,
        ),
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => decrypt_layered_chunk(
            root_key,
            payload_base_nonce,
            commitment,
            descriptor,
            ciphertext,
        ),
    }
}

fn encrypt_frame(
    suite: V3SuiteId,
    root_key: &[u8; 32],
    payload_base_nonce: &[u8; 24],
    commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => encrypt_xchacha_chunk(
            root_key,
            payload_base_nonce,
            commitment,
            descriptor,
            plaintext,
        ),
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => encrypt_layered_chunk(
            root_key,
            payload_base_nonce,
            commitment,
            descriptor,
            plaintext,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decrypt_payload_frames(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    plaintext_len: u64,
    payload_base_nonce: &[u8; 24],
    root_key: &[u8; 32],
    commitment: &[u8; 32],
    suite: V3SuiteId,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let count = frame_count(plaintext_len)?;
    let mut written = 0u64;
    for index in 0..count {
        let chunk_len = frame_plaintext_len(plaintext_len, index, count);
        let ciphertext = read_frame(reader, chunk_len + frame_tag_len(suite))?;
        let descriptor = V3ChunkDescriptor::new(index, chunk_len, index + 1 == count)?;
        let plaintext = Zeroizing::new(decrypt_frame(
            suite,
            root_key,
            payload_base_nonce,
            commitment,
            descriptor,
            &ciphertext,
        )?);
        writer.write_all(&plaintext)?;
        written = written
            .checked_add(plaintext.len() as u64)
            .ok_or(CryptoError::DecryptionFailed)?;
        if let Some(callback) = progress.as_deref_mut() {
            callback(written);
        }
    }
    if written != plaintext_len {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut suffix = [0];
    if reader.read(&mut suffix)? != 0 {
        return Err(CryptoError::DecryptionFailed);
    }
    Ok(())
}

fn decrypt_payload(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    envelope: &V3Envelope,
    envelope_bytes: &[u8],
    root_key: &[u8; 32],
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let suite = suite_from_id(envelope.suite_id)?;
    let commitment = envelope_commitment(root_key, suite, envelope_bytes)?;
    decrypt_payload_frames(
        reader,
        writer,
        envelope.plaintext_len,
        &envelope.payload_base_nonce,
        root_key,
        &commitment,
        suite,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt_payload_frames(
    input: &mut dyn Read,
    output: &mut dyn Write,
    plaintext_len: u64,
    payload_base_nonce: &[u8; 24],
    root_key: &[u8; 32],
    commitment: &[u8; 32],
    suite: V3SuiteId,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let count = frame_count(plaintext_len)?;
    let mut consumed = 0u64;
    for index in 0..count {
        let chunk_len = frame_plaintext_len(plaintext_len, index, count);
        let mut plaintext = Zeroizing::new(vec![0; chunk_len]);
        if let Err(error) = input.read_exact(&mut plaintext) {
            return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
                CryptoError::Validation("Input length changed during encryption")
            } else {
                CryptoError::Io(error)
            });
        }
        let descriptor = V3ChunkDescriptor::new(index, chunk_len, index + 1 == count)?;
        let ciphertext = encrypt_frame(
            suite,
            root_key,
            payload_base_nonce,
            commitment,
            descriptor,
            &plaintext,
        )?;
        output.write_all(&ciphertext)?;
        consumed = consumed
            .checked_add(chunk_len as u64)
            .ok_or(CryptoError::Validation("v3 plaintext length overflow"))?;
        if let Some(callback) = progress.as_deref_mut() {
            callback(consumed);
        }
    }
    let mut extra = [0];
    if consumed != plaintext_len || input.read(&mut extra)? != 0 {
        return Err(CryptoError::Validation(
            "Input length changed during encryption",
        ));
    }
    Ok(())
}

pub fn encrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    profile: SecurityProfile,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    encrypt_file_password_with_suite(
        input_path,
        output_path,
        password,
        profile,
        V3SuiteId::XChaCha20Poly1305,
        replace_existing,
        progress,
    )
}

/// Encrypt with an explicit experimental v3 payload suite.
///
/// The default writer stays single-layer `LV3-XC20P`; callers must pass
/// `V3SuiteId::Aes256GcmSivXChaCha20Poly1305` explicitly to opt into the
/// layered suite.
pub fn encrypt_file_password_with_suite(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    profile: SecurityProfile,
    suite: V3SuiteId,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    if password.expose_secret().is_empty() {
        return Err(CryptoError::Validation("Password must not be empty"));
    }
    let mut input = File::open(input_path)?;
    let plaintext_len = input.metadata()?.len();
    let mut rng = OsRng;
    let mut root_key = Zeroizing::new([0; 32]);
    rng.fill_bytes(&mut *root_key);

    let mut envelope = V3Envelope {
        magic: V3_MAGIC,
        version: V3_VERSION,
        suite_id: suite_wire_id(suite),
        profile_id: profile_id(&profile),
        kdf_id: V3_KDF_ARGON2ID_V13,
        salt: [0; 16],
        wrapping_nonce: [0; 24],
        encrypted_file_root_key: [0; 48],
        payload_base_nonce: [0; 24],
        plaintext_len,
    };
    rng.fill_bytes(&mut envelope.salt);
    rng.fill_bytes(&mut envelope.wrapping_nonce);
    rng.fill_bytes(&mut envelope.payload_base_nonce);

    let master_key = derive_master_key(
        &password,
        &envelope.salt,
        profile_costs(envelope.profile_id)?,
    )?;
    let wrapping_key = derive_wrapping_key(&master_key, suite)?;
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let wrapped = cipher
        .encrypt(
            &XNonce::from(envelope.wrapping_nonce),
            Payload {
                msg: &*root_key,
                aad: &wrap_aad(&envelope)?,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    envelope.encrypted_file_root_key = wrapped
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let envelope_bytes = encode_envelope(&envelope)?;
    let commitment = envelope_commitment(&root_key, suite, &envelope_bytes)?;
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
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
        suite,
        progress,
    )?;
    output.as_file().sync_all()?;
    persist_temp_path(output.into_temp_path(), output_path, replace_existing)?;
    Ok(())
}

pub fn decrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    // Encryption never creates empty-password capsules; fail before Argon2.
    if password.expose_secret().is_empty() {
        return Err(CryptoError::Validation("Password must not be empty"));
    }
    let mut input = File::open(input_path)?;
    let (envelope, envelope_bytes) = read_envelope(&mut input)?;
    let costs = validate_envelope(&envelope)?;
    let root_key = unwrap_root_key(&envelope, &password, costs)?;
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let mut output = NamedTempFile::new_in(parent)?;
    decrypt_payload(
        &mut input,
        &mut output,
        &envelope,
        &envelope_bytes,
        &root_key,
        progress,
    )?;
    output.as_file().sync_all()?;
    persist_temp_path(output.into_temp_path(), output_path, replace_existing)?;
    Ok(())
}

pub fn rotate_root_password(
    input_path: &Path,
    output_path: &Path,
    old_password: SecretString,
    new_password: SecretString,
    new_profile: SecurityProfile,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    if new_password.expose_secret().is_empty() {
        return Err(CryptoError::Validation("Password must not be empty"));
    }

    let suite = {
        let mut input = File::open(input_path)?;
        let (envelope, _) = read_envelope(&mut input)?;
        validate_envelope(&envelope)?;
        suite_from_id(envelope.suite_id)?
    };

    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let staging = tempdir_in(parent)?;
    let plaintext = staging.path().join("plaintext");
    match progress {
        Some(callback) => {
            decrypt_file_password(
                input_path,
                &plaintext,
                old_password,
                false,
                Some(&mut *callback),
            )?;
            encrypt_file_password_with_suite(
                &plaintext,
                output_path,
                new_password,
                new_profile,
                suite,
                replace_existing,
                Some(callback),
            )
        }
        None => {
            decrypt_file_password(input_path, &plaintext, old_password, false, None)?;
            encrypt_file_password_with_suite(
                &plaintext,
                output_path,
                new_password,
                new_profile,
                suite,
                replace_existing,
                None,
            )
        }
    }
}

pub fn verify_file_password(
    input_path: &Path,
    password: SecretString,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let mut input = File::open(input_path)?;
    let (envelope, envelope_bytes) = read_envelope(&mut input)?;
    let costs = validate_envelope(&envelope)?;
    let root_key = unwrap_root_key(&envelope, &password, costs)?;
    decrypt_payload(
        &mut input,
        &mut io::sink(),
        &envelope,
        &envelope_bytes,
        &root_key,
        progress,
    )
}

pub fn inspect_file(input_path: &Path) -> Result<V3FileInfo, CryptoError> {
    let mut input = File::open(input_path)?;
    let (envelope, _) = read_envelope(&mut input)?;
    let (m_cost, t_cost, p_cost) = validate_envelope(&envelope)?;
    Ok(V3FileInfo {
        envelope,
        m_cost,
        t_cost,
        p_cost,
    })
}

pub fn is_v3_file(input_path: &Path) -> Result<bool, CryptoError> {
    let mut input = File::open(input_path)?;
    let mut prefix = [0; 9];
    match input.read_exact(&mut prefix) {
        Ok(()) => Ok(prefix[4..9] == [b'L', b'V', b'A', b'U', 3]),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3FileRevision {
    LegacyPassword,
    HpkeRecipients,
    MutableSlots,
}

/// Select the v3 wire decoder from the fixed prefix before allocating the envelope.
pub fn file_revision(input_path: &Path) -> Result<V3FileRevision, CryptoError> {
    let mut input = File::open(input_path)?;
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if !(6..=V3_MUTABLE_MAX_ENVELOPE_SIZE).contains(&length) {
        return Err(CryptoError::Validation("v3 envelope size is invalid"));
    }

    let mut prefix = [0; 6];
    input.read_exact(&mut prefix).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::Validation("v3 envelope header is truncated")
        } else {
            CryptoError::Io(error)
        }
    })?;
    if prefix[..4] != V3_MAGIC || prefix[4] != V3_VERSION as u8 {
        return Err(CryptoError::Validation("Unsupported v3 envelope header"));
    }

    match prefix[5] {
        V3_SUITE_XCHACHA20_POLY1305 | V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305
            if length <= V3_MAX_ENVELOPE_SIZE =>
        {
            Ok(V3FileRevision::LegacyPassword)
        }
        V3_HPKE_ENVELOPE_REVISION if length <= V3_HPKE_MAX_ENVELOPE_SIZE => {
            Ok(V3FileRevision::HpkeRecipients)
        }
        V3_MUTABLE_ENVELOPE_REVISION if length <= V3_MUTABLE_MAX_ENVELOPE_SIZE => {
            Ok(V3FileRevision::MutableSlots)
        }
        _ => Err(CryptoError::Validation("Unsupported v3 envelope revision")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn password(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn v3_envelope_wrap_commitment_and_frame_match_fixed_vectors() {
        let envelope = V3Envelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            suite_id: V3_SUITE_XCHACHA20_POLY1305,
            profile_id: 0,
            kdf_id: V3_KDF_ARGON2ID_V13,
            salt: [0x10; 16],
            wrapping_nonce: [0x20; 24],
            encrypted_file_root_key: [0x30; 48],
            payload_base_nonce: [0x40; 24],
            plaintext_len: 42,
        };
        let envelope_bytes = encode_envelope(&envelope).unwrap();
        let wrap_aad = wrap_aad(&envelope).unwrap();
        let root_key = [0xa5; 32];
        let commitment =
            envelope_commitment(&root_key, V3SuiteId::XChaCha20Poly1305, &envelope_bytes).unwrap();
        let descriptor = V3ChunkDescriptor::new(0, 6, true).unwrap();
        let ciphertext = encrypt_xchacha_chunk(
            &root_key,
            &envelope.payload_base_nonce,
            &commitment,
            descriptor,
            b"vector",
        )
        .unwrap();

        assert_eq!(hex(&envelope_bytes), "4c56415503010001101010101010101010101010101010102020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040402a");
        assert_eq!(hex(&wrap_aad), "4c7661752076332070617373776f726420726f6f7420414144004c56415503010001101010101010101010101010101010102020202020202020202020202020202020202020202020204040404040404040404040404040404040404040404040402a");
        assert_eq!(
            hex(&commitment),
            "5bcfdc10143274765c441bcc3f1c879461348341d8891f70ee8025cd4b82baea"
        );
        assert_eq!(
            hex(&ciphertext),
            "9adca79709a2658834384ae5f79469fd82254b8eebb1"
        );
    }

    fn roundtrip(length: usize) {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        let output = dir.path().join("output");
        let bytes: Vec<u8> = (0..length).map(|index| index as u8).collect();
        fs::write(&input, &bytes).unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            password("test"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        decrypt_file_password(&encrypted, &output, password("test"), false, None).unwrap();
        assert_eq!(fs::read(output).unwrap(), bytes);
    }

    #[test]
    fn empty_partial_exact_and_multi_chunk_roundtrip() {
        for length in [
            0,
            31,
            V3_MAX_CHUNK_PLAINTEXT_LEN,
            V3_MAX_CHUNK_PLAINTEXT_LEN + 17,
        ] {
            roundtrip(length);
        }
    }

    fn roundtrip_with_suite(length: usize, suite: V3SuiteId) {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        let output = dir.path().join("output");
        let bytes: Vec<u8> = (0..length).map(|index| index as u8).collect();
        fs::write(&input, &bytes).unwrap();
        encrypt_file_password_with_suite(
            &input,
            &encrypted,
            password("test"),
            SecurityProfile::Fast,
            suite,
            false,
            None,
        )
        .unwrap();
        let info = inspect_file(&encrypted).unwrap();
        assert_eq!(info.envelope.suite_id, suite_wire_id(suite));
        verify_file_password(&encrypted, password("test"), None).unwrap();
        decrypt_file_password(&encrypted, &output, password("test"), false, None).unwrap();
        assert_eq!(fs::read(output).unwrap(), bytes);
    }

    #[test]
    fn layered_suite_empty_partial_exact_and_multi_chunk_roundtrip() {
        for length in [
            0,
            31,
            V3_MAX_CHUNK_PLAINTEXT_LEN,
            V3_MAX_CHUNK_PLAINTEXT_LEN + 17,
        ] {
            roundtrip_with_suite(length, V3SuiteId::Aes256GcmSivXChaCha20Poly1305);
        }
    }

    #[test]
    fn layered_suite_tamper_truncation_and_wrong_password_fail() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        fs::write(&input, b"layered authenticated payload").unwrap();
        encrypt_file_password_with_suite(
            &input,
            &encrypted,
            password("test"),
            SecurityProfile::Fast,
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&encrypted).unwrap();

        let cases = [
            ("wrong", original.clone()),
            ("truncated", original[..original.len() - 1].to_vec()),
            ("suffix", [original.as_slice(), b"x"].concat()),
            ("ciphertext", {
                let mut bytes = original.clone();
                *bytes.last_mut().unwrap() ^= 1;
                bytes
            }),
            ("envelope-wrap", {
                let envelope_len = u32::from_le_bytes(original[..4].try_into().unwrap()) as usize;
                let (mut envelope, trailing) =
                    postcard::take_from_bytes::<V3Envelope>(&original[4..4 + envelope_len])
                        .unwrap();
                assert!(trailing.is_empty());
                envelope.encrypted_file_root_key[0] ^= 1;
                let encoded = postcard::to_allocvec(&envelope).unwrap();
                let mut bytes = (encoded.len() as u32).to_le_bytes().to_vec();
                bytes.extend_from_slice(&encoded);
                bytes.extend_from_slice(&original[4 + envelope_len..]);
                bytes
            }),
        ];
        for (name, bytes) in cases {
            let damaged = dir.path().join(format!("{name}.lvau"));
            let output = dir.path().join(format!("{name}.out"));
            fs::write(&damaged, bytes).unwrap();
            let attempted_password = if name == "wrong" { "bad" } else { "test" };
            assert!(
                decrypt_file_password(
                    &damaged,
                    &output,
                    password(attempted_password),
                    false,
                    None,
                )
                .is_err(),
                "case {name} must fail"
            );
            assert!(!output.exists());
        }
    }

    #[test]
    fn layered_suite_envelope_identity_tamper_is_rejected() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        fs::write(&input, b"payload").unwrap();
        encrypt_file_password_with_suite(
            &input,
            &encrypted,
            password("test"),
            SecurityProfile::Fast,
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            false,
            None,
        )
        .unwrap();
        let bytes = fs::read(&encrypted).unwrap();
        let envelope_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let envelope_bytes = &bytes[4..4 + envelope_len];
        let (envelope, trailing) = postcard::take_from_bytes::<V3Envelope>(envelope_bytes).unwrap();
        assert!(trailing.is_empty());

        // Flipping the suite identifier to the single-layer suite must fail:
        // wrap key, commitment, nonces, and frame codecs all bind the suite.
        let downgraded = V3Envelope {
            suite_id: V3_SUITE_XCHACHA20_POLY1305,
            ..envelope.clone()
        };
        let encoded = postcard::to_allocvec(&downgraded).unwrap();
        let mut damaged = (encoded.len() as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&encoded);
        damaged.extend_from_slice(&bytes[4 + envelope_len..]);
        let path = dir.path().join("downgraded.lvau");
        let output = dir.path().join("downgraded.out");
        fs::write(&path, damaged).unwrap();
        assert!(decrypt_file_password(&path, &output, password("test"), false, None).is_err());
        assert!(!output.exists());

        // Unknown suite identifiers fail closed before KDF work.
        let unknown = V3Envelope {
            suite_id: 99,
            ..envelope.clone()
        };
        let encoded = postcard::to_allocvec(&unknown).unwrap();
        let mut damaged = (encoded.len() as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&encoded);
        damaged.extend_from_slice(&bytes[4 + envelope_len..]);
        let path = dir.path().join("unknown-suite.lvau");
        fs::write(&path, damaged).unwrap();
        assert!(inspect_file(&path).is_err());
    }

    #[test]
    fn rotate_root_password_preserves_the_layered_suite() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let original = dir.path().join("original.lvau");
        let rotated = dir.path().join("rotated.lvau");
        let rotated_output = dir.path().join("rotated.out");
        fs::write(&input, b"layered payload to rotate").unwrap();
        encrypt_file_password_with_suite(
            &input,
            &original,
            password("old"),
            SecurityProfile::Fast,
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            false,
            None,
        )
        .unwrap();

        rotate_root_password(
            &original,
            &rotated,
            password("old"),
            password("new"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();

        let rotated_info = inspect_file(&rotated).unwrap();
        assert_eq!(
            rotated_info.envelope.suite_id,
            V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305
        );
        assert_eq!(
            payload_suite_name(V3SuiteId::Aes256GcmSivXChaCha20Poly1305),
            "LV3-AESGCMSIV-XC20P"
        );
        verify_file_password(&rotated, password("new"), None).unwrap();
        assert!(verify_file_password(&rotated, password("old"), None).is_err());
        decrypt_file_password(&rotated, &rotated_output, password("new"), false, None).unwrap();
        assert_eq!(
            fs::read(rotated_output).unwrap(),
            b"layered payload to rotate"
        );
    }

    #[test]
    fn empty_password_cannot_create_a_v3_capsule() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let output = dir.path().join("output.lvau");
        fs::write(&input, b"payload").unwrap();

        assert!(matches!(
            encrypt_file_password(
                &input,
                &output,
                password(""),
                SecurityProfile::Fast,
                false,
                None,
            ),
            Err(CryptoError::Validation("Password must not be empty"))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn rotate_root_password_reencrypts_for_the_new_password() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let original = dir.path().join("original.lvau");
        let rotated = dir.path().join("rotated.lvau");
        let original_output = dir.path().join("original.out");
        let rotated_output = dir.path().join("rotated.out");
        fs::write(&input, b"payload to rotate").unwrap();
        encrypt_file_password(
            &input,
            &original,
            password("old"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let original_bytes = fs::read(&original).unwrap();

        rotate_root_password(
            &original,
            &rotated,
            password("old"),
            password("new"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();

        verify_file_password(&rotated, password("new"), None).unwrap();
        assert!(verify_file_password(&rotated, password("old"), None).is_err());
        decrypt_file_password(&rotated, &rotated_output, password("new"), false, None).unwrap();
        assert_eq!(fs::read(rotated_output).unwrap(), b"payload to rotate");
        decrypt_file_password(&original, &original_output, password("old"), false, None).unwrap();
        assert_eq!(fs::read(original_output).unwrap(), b"payload to rotate");
        assert_eq!(fs::read(&original).unwrap(), original_bytes);

        let original_info = inspect_file(&original).unwrap();
        let rotated_info = inspect_file(&rotated).unwrap();
        assert_ne!(original_info.envelope.salt, rotated_info.envelope.salt);
        assert_ne!(
            original_info.envelope.wrapping_nonce,
            rotated_info.envelope.wrapping_nonce
        );
        assert_ne!(
            original_info.envelope.payload_base_nonce,
            rotated_info.envelope.payload_base_nonce
        );
        assert_ne!(
            original_info.envelope.encrypted_file_root_key,
            rotated_info.envelope.encrypted_file_root_key
        );
    }

    #[test]
    fn rotate_root_password_rejects_wrong_or_empty_password_without_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let original = dir.path().join("original.lvau");
        let output = dir.path().join("rotated.lvau");
        fs::write(&input, b"payload").unwrap();
        encrypt_file_password(
            &input,
            &original,
            password("old"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let original_bytes = fs::read(&original).unwrap();

        assert!(rotate_root_password(
            &original,
            &output,
            password("wrong"),
            password("new"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .is_err());
        assert!(!output.exists());
        assert_eq!(fs::read(&original).unwrap(), original_bytes);

        assert!(matches!(
            rotate_root_password(
                &original,
                &output,
                password("old"),
                password(""),
                SecurityProfile::Fast,
                false,
                None,
            ),
            Err(CryptoError::Validation("Password must not be empty"))
        ));
        assert!(!output.exists());
        assert_eq!(fs::read(&original).unwrap(), original_bytes);
    }

    #[test]
    fn rotate_root_password_preserves_existing_output_unless_replacement_is_requested() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let original = dir.path().join("original.lvau");
        let output = dir.path().join("rotated.lvau");
        fs::write(&input, b"payload").unwrap();
        encrypt_file_password(
            &input,
            &original,
            password("old"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let original_bytes = fs::read(&original).unwrap();
        fs::write(&output, b"keep me").unwrap();

        assert!(rotate_root_password(
            &original,
            &output,
            password("old"),
            password("new"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .is_err());
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
        assert_eq!(fs::read(&original).unwrap(), original_bytes);

        rotate_root_password(
            &original,
            &output,
            password("old"),
            password("new"),
            SecurityProfile::Fast,
            true,
            None,
        )
        .unwrap();
        verify_file_password(&output, password("new"), None).unwrap();
        assert_eq!(fs::read(&original).unwrap(), original_bytes);
    }

    #[test]
    fn rotate_root_password_rejects_corrupt_input_without_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        fs::write(&input, b"authenticated payload").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            password("old"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&encrypted).unwrap();

        for (name, bytes) in [
            ("malformed", vec![0xff; 12]),
            ("truncated", original[..original.len() - 1].to_vec()),
            ("tag", {
                let mut bytes = original.clone();
                *bytes.last_mut().unwrap() ^= 1;
                bytes
            }),
        ] {
            let damaged = dir.path().join(format!("{name}.lvau"));
            let output = dir.path().join(format!("{name}.rotated.lvau"));
            fs::write(&damaged, bytes).unwrap();
            assert!(rotate_root_password(
                &damaged,
                &output,
                password("old"),
                password("new"),
                SecurityProfile::Fast,
                false,
                None,
            )
            .is_err());
            assert!(!output.exists());
            assert_eq!(fs::read(&encrypted).unwrap(), original);
        }
    }

    #[test]
    fn tamper_truncation_suffix_and_wrong_password_fail_without_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        fs::write(&input, b"authenticated payload").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            password("test"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let original = fs::read(&encrypted).unwrap();

        let cases = [
            ("wrong", original.clone()),
            ("truncated", original[..original.len() - 1].to_vec()),
            ("suffix", [original.as_slice(), b"x"].concat()),
            ("ciphertext", {
                let mut bytes = original.clone();
                *bytes.last_mut().unwrap() ^= 1;
                bytes
            }),
        ];
        for (name, bytes) in cases {
            let damaged = dir.path().join(format!("{name}.lvau"));
            let output = dir.path().join(format!("{name}.out"));
            fs::write(&damaged, bytes).unwrap();
            let attempted_password = if name == "wrong" { "bad" } else { "test" };
            assert!(decrypt_file_password(
                &damaged,
                &output,
                password(attempted_password),
                false,
                None,
            )
            .is_err());
            assert!(!output.exists());
        }

        let envelope_len = u32::from_le_bytes(original[..4].try_into().unwrap()) as usize;
        let (mut envelope, trailing) =
            postcard::take_from_bytes::<V3Envelope>(&original[4..4 + envelope_len]).unwrap();
        assert!(trailing.is_empty());
        envelope.encrypted_file_root_key[0] ^= 1;
        let encoded = postcard::to_allocvec(&envelope).unwrap();
        let damaged = dir.path().join("envelope.lvau");
        let output = dir.path().join("envelope.out");
        let mut bytes = (encoded.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&encoded);
        bytes.extend_from_slice(&original[4 + envelope_len..]);
        fs::write(&damaged, bytes).unwrap();
        assert!(decrypt_file_password(&damaged, &output, password("test"), false, None).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn envelope_suite_and_profile_tamper_are_rejected() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("encrypted");
        fs::write(&input, b"payload").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            password("test"),
            SecurityProfile::Fast,
            false,
            None,
        )
        .unwrap();
        let bytes = fs::read(&encrypted).unwrap();
        let envelope_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let envelope_bytes = &bytes[4..4 + envelope_len];
        let (envelope, trailing) = postcard::take_from_bytes::<V3Envelope>(envelope_bytes).unwrap();
        assert!(trailing.is_empty());

        for altered in [
            V3Envelope {
                suite_id: 99,
                ..envelope.clone()
            },
            V3Envelope {
                profile_id: 99,
                ..envelope.clone()
            },
            V3Envelope {
                magic: *b"NOPE",
                ..envelope.clone()
            },
        ] {
            let encoded = postcard::to_allocvec(&altered).unwrap();
            let mut damaged = Vec::new();
            damaged.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            damaged.extend_from_slice(&encoded);
            damaged.extend_from_slice(&bytes[4 + envelope_len..]);
            let path = dir.path().join(format!("tampered-{}", altered.profile_id));
            fs::write(&path, damaged).unwrap();
            assert!(inspect_file(&path).is_err());
        }

        // Suite 2 is a supported layered suite, so flipping the suite byte on
        // a single-layer file passes inspection but must fail decryption: the
        // root-wrap key, commitment, nonces, and frame codecs all bind it.
        let relabeled = V3Envelope {
            suite_id: V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305,
            ..envelope.clone()
        };
        let encoded = postcard::to_allocvec(&relabeled).unwrap();
        let mut damaged = (encoded.len() as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&encoded);
        damaged.extend_from_slice(&bytes[4 + envelope_len..]);
        let path = dir.path().join("relabeled-suite");
        let output = dir.path().join("relabeled-suite.out");
        fs::write(&path, damaged).unwrap();
        assert!(inspect_file(&path).is_ok());
        assert!(decrypt_file_password(&path, &output, password("test"), false, None).is_err());
        assert!(!output.exists());

        let trailing_envelope = dir.path().join("trailing-envelope");
        let mut encoded = envelope_bytes.to_vec();
        encoded.push(0);
        let mut damaged = (encoded.len() as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&encoded);
        damaged.extend_from_slice(&bytes[4 + envelope_len..]);
        fs::write(&trailing_envelope, damaged).unwrap();
        assert!(inspect_file(&trailing_envelope).is_err());

        let short_envelope = dir.path().join("short-envelope");
        let mut damaged = ((envelope_len - 1) as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&bytes[4..]);
        fs::write(&short_envelope, damaged).unwrap();
        assert!(inspect_file(&short_envelope).is_err());
    }
}

//! Format-v3 payload-suite primitives.
//!
//! It provides compatibility-sensitive suite identifiers, domain-separated
//! keys, nonces, chunk AAD, and the experimental single-file implementation.

#[path = "v3_convert_file.rs"]
pub mod convert_file;
#[path = "v3_file.rs"]
pub mod file;
#[path = "v3_hpke_file.rs"]
pub mod hpke_file;
#[path = "v3_mlkem.rs"]
mod mlkem;
#[path = "v3_mutable_file.rs"]
pub mod mutable_file;
#[path = "v3_rekey_file.rs"]
pub mod rekey_file;

use aes_gcm_siv::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
    Aes256GcmSiv, Nonce as AesNonce,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

use super::V3SuiteId;

const KEY_SCHEDULE_DOMAIN: &[u8] = b"Lvau v3 key schedule\0";
const SUBKEY_INFO_DOMAIN: &[u8] = b"Lvau v3 subkey\0";
const NONCE_SCHEDULE_DOMAIN: &[u8] = b"Lvau v3 nonce schedule\0";
const CHUNK_AAD_DOMAIN: &[u8] = b"Lvau v3 chunk AAD\0";
const XCHACHA_TAG_LEN: usize = 16;
const AES_GCM_SIV_TAG_LEN: usize = 16;
/// Maximum plaintext bytes accepted by one format-v3 chunk primitive.
pub const V3_MAX_CHUNK_PLAINTEXT_LEN: usize = 1024 * 1024;

/// The layer position committed by a v3 chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum V3Layer {
    Single = 1,
    Inner = 2,
    Outer = 3,
}

/// Domain-separated keys derived from a random v3 file root key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V3KeyPurpose {
    PayloadSingle,
    PayloadInnerAes256GcmSiv,
    PayloadOuterXChaCha20Poly1305,
    RecipientWrap,
    EnvelopeCommitment,
    BundleManifest,
    Padding,
    Exporter,
}

impl V3KeyPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::PayloadSingle => b"payload-single",
            Self::PayloadInnerAes256GcmSiv => b"payload-inner-aes-256-gcm-siv",
            Self::PayloadOuterXChaCha20Poly1305 => b"payload-outer-xchacha20-poly1305",
            Self::RecipientWrap => b"recipient-wrap",
            Self::EnvelopeCommitment => b"envelope-commitment",
            Self::BundleManifest => b"bundle-manifest",
            Self::Padding => b"padding",
            Self::Exporter => b"exporter",
        }
    }
}

/// Public lengths and frame position committed by a v3 chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3ChunkDescriptor {
    pub index: u64,
    pub plaintext_len: u32,
    pub final_chunk: bool,
}

impl V3ChunkDescriptor {
    pub fn new(index: u64, plaintext_len: usize, final_chunk: bool) -> Result<Self, CryptoError> {
        let plaintext_len = u32::try_from(plaintext_len)
            .map_err(|_| CryptoError::Validation("v3 chunk plaintext is too large"))?;
        validate_plaintext_len(plaintext_len)?;
        Ok(Self {
            index,
            plaintext_len,
            final_chunk,
        })
    }
}

/// Return the fixed wire name for an experimental v3 payload suite.
pub const fn suite_wire_name(suite: V3SuiteId) -> &'static str {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => "LV3-XC20P",
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => "LV3-AESGCMSIV-XC20P",
    }
}

const fn suite_code(suite: V3SuiteId) -> u8 {
    match suite {
        V3SuiteId::XChaCha20Poly1305 => 1,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => 2,
    }
}

/// Derive one independent 256-bit key from the random file root key.
pub fn derive_subkey(
    root_key: &[u8; 32],
    suite: V3SuiteId,
    purpose: V3KeyPurpose,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let suite_name = suite_wire_name(suite).as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(KEY_SCHEDULE_DOMAIN), root_key);

    let mut info =
        Vec::with_capacity(SUBKEY_INFO_DOMAIN.len() + suite_name.len() + 1 + purpose.label().len());
    info.extend_from_slice(SUBKEY_INFO_DOMAIN);
    info.extend_from_slice(suite_name);
    info.push(0);
    info.extend_from_slice(purpose.label());

    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(key)
}

fn derive_nonce<const N: usize>(
    base_nonce: &[u8],
    suite: V3SuiteId,
    layer: V3Layer,
    chunk_index: u64,
) -> Result<[u8; N], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(NONCE_SCHEDULE_DOMAIN), base_nonce);
    let mut info = [0u8; 10];
    info[0] = suite_code(suite);
    info[1] = layer as u8;
    info[2..].copy_from_slice(&chunk_index.to_le_bytes());

    let mut nonce = [0u8; N];
    hk.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(nonce)
}

/// Derive the XChaCha20-Poly1305 nonce for one v3 chunk and layer.
pub fn derive_xchacha_nonce(
    base_nonce: &[u8; 24],
    suite: V3SuiteId,
    layer: V3Layer,
    chunk_index: u64,
) -> Result<[u8; 24], CryptoError> {
    derive_nonce(base_nonce, suite, layer, chunk_index)
}

/// Derive the AES-256-GCM-SIV nonce reserved for the layered v3 suite.
///
/// The cipher backend is intentionally not wired into the writer yet.
pub fn derive_aes_gcm_siv_nonce(
    base_nonce: &[u8; 12],
    chunk_index: u64,
) -> Result<[u8; 12], CryptoError> {
    derive_nonce(
        base_nonce,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
        V3Layer::Inner,
        chunk_index,
    )
}

/// Construct canonical v3 chunk AAD.
///
/// Layout:
/// `domain || suite || layer || commitment || index || plaintext_len ||
/// inner_len || ciphertext_len || final`.
pub fn chunk_aad(
    suite: V3SuiteId,
    layer: V3Layer,
    envelope_commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    inner_len: u32,
    ciphertext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 55);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.push(suite_code(suite));
    aad.push(layer as u8);
    aad.extend_from_slice(envelope_commitment);
    aad.extend_from_slice(&descriptor.index.to_le_bytes());
    aad.extend_from_slice(&descriptor.plaintext_len.to_le_bytes());
    aad.extend_from_slice(&inner_len.to_le_bytes());
    aad.extend_from_slice(&ciphertext_len.to_le_bytes());
    aad.push(u8::from(descriptor.final_chunk));
    aad
}

fn validate_plaintext_len(plaintext_len: u32) -> Result<usize, CryptoError> {
    let plaintext_len = usize::try_from(plaintext_len)
        .map_err(|_| CryptoError::Validation("v3 chunk plaintext length is invalid"))?;
    if plaintext_len > V3_MAX_CHUNK_PLAINTEXT_LEN {
        return Err(CryptoError::Validation(
            "v3 chunk plaintext exceeds the format limit",
        ));
    }
    Ok(plaintext_len)
}

fn checked_single_layer_ciphertext_len(plaintext_len: u32) -> Result<u32, CryptoError> {
    plaintext_len
        .checked_add(XCHACHA_TAG_LEN as u32)
        .ok_or(CryptoError::Validation(
            "v3 chunk ciphertext length overflow",
        ))
}

/// Encrypt one v3 `LV3-XC20P` chunk.
///
/// This is a chunk primitive, not a capsule writer. Callers must still enforce
/// the envelope-level chunk size, final-frame, and total-length invariants.
pub fn encrypt_xchacha_chunk(
    root_key: &[u8; 32],
    base_nonce: &[u8; 24],
    envelope_commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let plaintext_len = validate_plaintext_len(descriptor.plaintext_len)?;
    if plaintext.len() != plaintext_len {
        return Err(CryptoError::Validation(
            "v3 chunk plaintext length does not match its descriptor",
        ));
    }

    let suite = V3SuiteId::XChaCha20Poly1305;
    let ciphertext_len = checked_single_layer_ciphertext_len(descriptor.plaintext_len)?;
    let aad = chunk_aad(
        suite,
        V3Layer::Single,
        envelope_commitment,
        descriptor,
        0,
        ciphertext_len,
    );
    let key = derive_subkey(root_key, suite, V3KeyPurpose::PayloadSingle)?;
    let nonce = derive_xchacha_nonce(base_nonce, suite, V3Layer::Single, descriptor.index)?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Authenticate and decrypt one v3 `LV3-XC20P` chunk.
pub fn decrypt_xchacha_chunk(
    root_key: &[u8; 32],
    base_nonce: &[u8; 24],
    envelope_commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let plaintext_len = validate_plaintext_len(descriptor.plaintext_len)?;
    let expected_len = checked_single_layer_ciphertext_len(descriptor.plaintext_len)?;
    let actual_len = u32::try_from(ciphertext.len())
        .map_err(|_| CryptoError::Validation("v3 chunk ciphertext is too large"))?;
    if actual_len != expected_len {
        return Err(CryptoError::DecryptionFailed);
    }

    let suite = V3SuiteId::XChaCha20Poly1305;
    let aad = chunk_aad(
        suite,
        V3Layer::Single,
        envelope_commitment,
        descriptor,
        0,
        expected_len,
    );
    let key = derive_subkey(root_key, suite, V3KeyPurpose::PayloadSingle)?;
    let nonce = derive_xchacha_nonce(base_nonce, suite, V3Layer::Single, descriptor.index)?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if plaintext.len() != plaintext_len {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(plaintext)
}

/// Derive the per-chunk AES-256-GCM-SIV nonce for the layered v3 suite.
///
/// The 24-byte file `payload_base_nonce` remains the only stored randomness;
/// the 12-byte inner nonce is HKDF-derived from it under the layered suite and
/// inner-layer domain, keeping it independent from every XChaCha nonce domain.
pub fn derive_layered_inner_nonce(
    base_nonce: &[u8; 24],
    chunk_index: u64,
) -> Result<[u8; 12], CryptoError> {
    derive_nonce(
        base_nonce,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
        V3Layer::Inner,
        chunk_index,
    )
}

fn checked_layered_ciphertext_len(plaintext_len: u32) -> Result<(u32, u32), CryptoError> {
    let inner_len = plaintext_len
        .checked_add(AES_GCM_SIV_TAG_LEN as u32)
        .ok_or(CryptoError::Validation(
            "v3 chunk ciphertext length overflow",
        ))?;
    let outer_len =
        inner_len
            .checked_add(XCHACHA_TAG_LEN as u32)
            .ok_or(CryptoError::Validation(
                "v3 chunk ciphertext length overflow",
            ))?;
    Ok((inner_len, outer_len))
}

/// Encrypt one v3 `LV3-AESGCMSIV-XC20P` chunk.
///
/// Fixed order: AES-256-GCM-SIV inner encryption first, then XChaCha20-Poly1305
/// outer encryption over the inner ciphertext. Each layer uses its own
/// domain-separated key and nonce domain, and each layer's AAD commits to the
/// suite, layer position, envelope commitment, chunk index, lengths, and
/// final-frame state.
pub fn encrypt_layered_chunk(
    root_key: &[u8; 32],
    base_nonce: &[u8; 24],
    envelope_commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let suite = V3SuiteId::Aes256GcmSivXChaCha20Poly1305;
    let plaintext_len = validate_plaintext_len(descriptor.plaintext_len)?;
    if plaintext.len() != plaintext_len {
        return Err(CryptoError::Validation(
            "v3 chunk plaintext length does not match its descriptor",
        ));
    }
    let (inner_len, outer_len) = checked_layered_ciphertext_len(descriptor.plaintext_len)?;

    let inner_key = derive_subkey(root_key, suite, V3KeyPurpose::PayloadInnerAes256GcmSiv)?;
    let inner_nonce = derive_layered_inner_nonce(base_nonce, descriptor.index)?;
    let inner_aad = chunk_aad(
        suite,
        V3Layer::Inner,
        envelope_commitment,
        descriptor,
        0,
        inner_len,
    );
    let inner_cipher = Aes256GcmSiv::new((&*inner_key).into());
    let inner_ciphertext = Zeroizing::new(
        inner_cipher
            .encrypt(
                &AesNonce::from(inner_nonce),
                AesPayload {
                    msg: plaintext,
                    aad: &inner_aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?,
    );
    debug_assert_eq!(inner_ciphertext.len() as u32, inner_len);

    let outer_key = derive_subkey(root_key, suite, V3KeyPurpose::PayloadOuterXChaCha20Poly1305)?;
    let outer_nonce = derive_xchacha_nonce(base_nonce, suite, V3Layer::Outer, descriptor.index)?;
    let outer_aad = chunk_aad(
        suite,
        V3Layer::Outer,
        envelope_commitment,
        descriptor,
        inner_len,
        outer_len,
    );
    let outer_cipher = XChaCha20Poly1305::new(outer_key.as_ref().into());
    outer_cipher
        .encrypt(
            &XNonce::from(outer_nonce),
            Payload {
                msg: &inner_ciphertext,
                aad: &outer_aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Authenticate and decrypt one v3 `LV3-AESGCMSIV-XC20P` chunk.
///
/// The outer XChaCha20-Poly1305 layer is authenticated first; the inner
/// AES-256-GCM-SIV layer is authenticated before any plaintext is released.
pub fn decrypt_layered_chunk(
    root_key: &[u8; 32],
    base_nonce: &[u8; 24],
    envelope_commitment: &[u8; 32],
    descriptor: V3ChunkDescriptor,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let suite = V3SuiteId::Aes256GcmSivXChaCha20Poly1305;
    let plaintext_len = validate_plaintext_len(descriptor.plaintext_len)?;
    let (inner_len, outer_len) = checked_layered_ciphertext_len(descriptor.plaintext_len)?;
    let actual_len = u32::try_from(ciphertext.len())
        .map_err(|_| CryptoError::Validation("v3 chunk ciphertext is too large"))?;
    if actual_len != outer_len {
        return Err(CryptoError::DecryptionFailed);
    }

    let outer_key = derive_subkey(root_key, suite, V3KeyPurpose::PayloadOuterXChaCha20Poly1305)?;
    let outer_nonce = derive_xchacha_nonce(base_nonce, suite, V3Layer::Outer, descriptor.index)?;
    let outer_aad = chunk_aad(
        suite,
        V3Layer::Outer,
        envelope_commitment,
        descriptor,
        inner_len,
        outer_len,
    );
    let outer_cipher = XChaCha20Poly1305::new(outer_key.as_ref().into());
    let inner_ciphertext = Zeroizing::new(
        outer_cipher
            .decrypt(
                &XNonce::from(outer_nonce),
                Payload {
                    msg: ciphertext,
                    aad: &outer_aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    if inner_ciphertext.len() as u32 != inner_len {
        return Err(CryptoError::DecryptionFailed);
    }

    let inner_key = derive_subkey(root_key, suite, V3KeyPurpose::PayloadInnerAes256GcmSiv)?;
    let inner_nonce = derive_layered_inner_nonce(base_nonce, descriptor.index)?;
    let inner_aad = chunk_aad(
        suite,
        V3Layer::Inner,
        envelope_commitment,
        descriptor,
        0,
        inner_len,
    );
    let inner_cipher = Aes256GcmSiv::new((&*inner_key).into());
    let plaintext = inner_cipher
        .decrypt(
            &AesNonce::from(inner_nonce),
            AesPayload {
                msg: &inner_ciphertext,
                aad: &inner_aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if plaintext.len() != plaintext_len {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        let bytes = value.as_bytes();
        (0..bytes.len())
            .step_by(2)
            .map(|start| {
                let pair = std::str::from_utf8(&bytes[start..start + 2]).expect("ASCII hex");
                u8::from_str_radix(pair, 16).expect("valid hex")
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn suite_wire_names_are_stable() {
        assert_eq!(suite_wire_name(V3SuiteId::XChaCha20Poly1305), "LV3-XC20P");
        assert_eq!(
            suite_wire_name(V3SuiteId::Aes256GcmSivXChaCha20Poly1305),
            "LV3-AESGCMSIV-XC20P"
        );
    }

    #[test]
    fn key_schedule_vector_is_stable() {
        let key = derive_subkey(
            &[0x42; 32],
            V3SuiteId::XChaCha20Poly1305,
            V3KeyPurpose::PayloadSingle,
        )
        .expect("derive v3 key");
        assert_eq!(
            key.as_ref(),
            decode_hex("2a99846610f53959b98726afb338e2736b1d03ec1e5d7b488943f29560ad69c3")
                .as_slice()
        );
    }

    #[test]
    fn nonce_and_aad_vectors_are_stable() {
        let index = 0x0102_0304_0506_0708;
        let nonce = derive_xchacha_nonce(
            &[0xA5; 24],
            V3SuiteId::XChaCha20Poly1305,
            V3Layer::Single,
            index,
        )
        .expect("derive v3 nonce");
        assert_eq!(
            nonce.as_slice(),
            decode_hex("baf867a6f363871f25add9708e1ba733f85c71a59ea6c8f3").as_slice()
        );

        let aad = chunk_aad(
            V3SuiteId::XChaCha20Poly1305,
            V3Layer::Single,
            &[0x11; 32],
            V3ChunkDescriptor {
                index,
                plaintext_len: 1234,
                final_chunk: true,
            },
            0,
            1250,
        );
        assert_eq!(
            aad,
            decode_hex(
                "4c766175207633206368756e6b20414144000101\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 0807060504030201d204000000000000e204000001"
                    .replace(char::is_whitespace, "")
                    .as_str()
            )
        );
    }

    #[test]
    fn xchacha_chunk_roundtrip_and_context_binding() {
        let root_key = [0x21; 32];
        let base_nonce = [0x53; 24];
        let commitment = [0x89; 32];
        let plaintext = b"v3 chunk payload";
        let descriptor =
            V3ChunkDescriptor::new(7, plaintext.len(), true).expect("valid descriptor");

        let ciphertext =
            encrypt_xchacha_chunk(&root_key, &base_nonce, &commitment, descriptor, plaintext)
                .expect("encrypt chunk");
        assert_eq!(ciphertext.len(), plaintext.len() + XCHACHA_TAG_LEN);

        let decrypted =
            decrypt_xchacha_chunk(&root_key, &base_nonce, &commitment, descriptor, &ciphertext)
                .expect("decrypt chunk");
        assert_eq!(decrypted, plaintext);

        let wrong_index =
            V3ChunkDescriptor::new(8, plaintext.len(), true).expect("valid descriptor");
        assert!(decrypt_xchacha_chunk(
            &root_key,
            &base_nonce,
            &commitment,
            wrong_index,
            &ciphertext,
        )
        .is_err());

        let wrong_final =
            V3ChunkDescriptor::new(7, plaintext.len(), false).expect("valid descriptor");
        assert!(decrypt_xchacha_chunk(
            &root_key,
            &base_nonce,
            &commitment,
            wrong_final,
            &ciphertext,
        )
        .is_err());

        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert!(
            decrypt_xchacha_chunk(&root_key, &base_nonce, &commitment, descriptor, &tampered,)
                .is_err()
        );
    }

    #[test]
    fn xchacha_chunk_rejects_a_different_suite_domain() {
        let root_key = [0x31; 32];
        let base_nonce = [0x72; 24];
        let commitment = [0xA4; 32];
        let plaintext = b"suite-bound payload";
        let descriptor =
            V3ChunkDescriptor::new(3, plaintext.len(), true).expect("valid descriptor");
        let ciphertext_len = checked_single_layer_ciphertext_len(descriptor.plaintext_len)
            .expect("valid ciphertext length");

        // Keep the purpose, layer, and chunk context identical so only the
        // suite identity changes the key, nonce, and AAD domains.
        let suite = V3SuiteId::Aes256GcmSivXChaCha20Poly1305;
        let key = derive_subkey(&root_key, suite, V3KeyPurpose::PayloadSingle)
            .expect("derive cross-suite test key");
        let nonce = derive_xchacha_nonce(&base_nonce, suite, V3Layer::Single, descriptor.index)
            .expect("derive cross-suite test nonce");
        let aad = chunk_aad(
            suite,
            V3Layer::Single,
            &commitment,
            descriptor,
            0,
            ciphertext_len,
        );
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("encrypt under alternate suite domain");

        assert!(decrypt_xchacha_chunk(
            &root_key,
            &base_nonce,
            &commitment,
            descriptor,
            &ciphertext,
        )
        .is_err());
    }

    #[test]
    fn layered_chunk_roundtrip_and_context_binding() {
        let root_key = [0x21; 32];
        let base_nonce = [0x53; 24];
        let commitment = [0x89; 32];
        let plaintext = b"v3 layered payload";
        let descriptor =
            V3ChunkDescriptor::new(7, plaintext.len(), true).expect("valid descriptor");

        let ciphertext =
            encrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, plaintext)
                .expect("encrypt layered chunk");
        assert_eq!(ciphertext.len(), plaintext.len() + 32);

        let decrypted =
            decrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, &ciphertext)
                .expect("decrypt layered chunk");
        assert_eq!(decrypted, plaintext);

        for altered in [
            V3ChunkDescriptor::new(8, plaintext.len(), true).expect("valid descriptor"),
            V3ChunkDescriptor::new(7, plaintext.len(), false).expect("valid descriptor"),
        ] {
            assert!(decrypt_layered_chunk(
                &root_key,
                &base_nonce,
                &commitment,
                altered,
                &ciphertext,
            )
            .is_err());
        }

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(
            decrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, &tampered,)
                .is_err()
        );

        let mut tampered_inner = ciphertext.clone();
        let last = tampered_inner.len() - 1;
        tampered_inner[last] ^= 1;
        assert!(decrypt_layered_chunk(
            &root_key,
            &base_nonce,
            &commitment,
            descriptor,
            &tampered_inner,
        )
        .is_err());

        assert!(decrypt_layered_chunk(
            &root_key,
            &base_nonce,
            &commitment,
            descriptor,
            &ciphertext[..ciphertext.len() - 1],
        )
        .is_err());

        let mismatch = V3ChunkDescriptor::new(0, 2, true).expect("valid descriptor");
        assert!(
            encrypt_layered_chunk(&[0x01; 32], &[0x02; 24], &[0x03; 32], mismatch, b"one",)
                .is_err()
        );
    }

    #[test]
    fn layered_chunk_rejects_single_layer_ciphertext_and_vice_versa() {
        let root_key = [0x31; 32];
        let base_nonce = [0x72; 24];
        let commitment = [0xA4; 32];
        let plaintext = b"cross-suite payload";
        let descriptor =
            V3ChunkDescriptor::new(3, plaintext.len(), true).expect("valid descriptor");

        let single =
            encrypt_xchacha_chunk(&root_key, &base_nonce, &commitment, descriptor, plaintext)
                .expect("encrypt single chunk");
        assert!(
            decrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, &single,)
                .is_err()
        );

        let layered =
            encrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, plaintext)
                .expect("encrypt layered chunk");
        assert!(
            decrypt_xchacha_chunk(&root_key, &base_nonce, &commitment, descriptor, &layered,)
                .is_err()
        );
        assert_ne!(single, layered);
    }

    #[test]
    fn descriptor_length_mismatch_fails_before_encryption() {
        let descriptor = V3ChunkDescriptor::new(0, 2, true).expect("valid descriptor");
        assert!(
            encrypt_xchacha_chunk(&[0x01; 32], &[0x02; 24], &[0x03; 32], descriptor, b"one",)
                .is_err()
        );
    }

    #[test]
    fn oversized_chunks_fail_before_aead_processing() {
        let oversized_len = V3_MAX_CHUNK_PLAINTEXT_LEN + 1;
        assert!(V3ChunkDescriptor::new(0, oversized_len, true).is_err());

        let descriptor = V3ChunkDescriptor {
            index: 0,
            plaintext_len: u32::try_from(oversized_len).expect("test length fits u32"),
            final_chunk: true,
        };
        assert!(matches!(
            decrypt_xchacha_chunk(&[0x01; 32], &[0x02; 24], &[0x03; 32], descriptor, &[],),
            Err(CryptoError::Validation(
                "v3 chunk plaintext exceeds the format limit"
            ))
        ));
    }

    #[test]
    fn layered_chunk_fixed_vector() {
        let root_key = [0x77; 32];
        let base_nonce = [0x88; 24];
        let commitment = [0x99; 32];
        let plaintext = b"layered vector";
        let descriptor =
            V3ChunkDescriptor::new(0, plaintext.len(), false).expect("valid descriptor");
        let (inner_len, outer_len) =
            checked_layered_ciphertext_len(descriptor.plaintext_len).expect("lengths");
        assert_eq!((inner_len, outer_len), (30, 46));

        let inner_nonce = derive_layered_inner_nonce(&base_nonce, 0).expect("inner nonce");
        assert_eq!(hex(&inner_nonce), "607af7ec0d9d76d8dd6a1ec4");

        let outer_nonce = derive_xchacha_nonce(
            &base_nonce,
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            V3Layer::Outer,
            0,
        )
        .expect("outer nonce");
        assert_eq!(
            hex(&outer_nonce),
            "9691a51e954c8da7a433f5f1ecd2f220820f8defb354b0d3"
        );

        let inner_aad = chunk_aad(
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            V3Layer::Inner,
            &commitment,
            descriptor,
            0,
            inner_len,
        );
        assert_eq!(
            hex(&inner_aad),
            "4c766175207633206368756e6b20414144000202999999999999999999999999999999999999999999999999999999999999999900000000000000000e000000000000001e00000000"
        );

        let outer_aad = chunk_aad(
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            V3Layer::Outer,
            &commitment,
            descriptor,
            inner_len,
            outer_len,
        );
        assert_eq!(
            hex(&outer_aad),
            "4c766175207633206368756e6b20414144000203999999999999999999999999999999999999999999999999999999999999999900000000000000000e0000001e0000002e00000000"
        );

        let ciphertext =
            encrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, plaintext)
                .expect("encrypt");
        assert_eq!(
            hex(&ciphertext),
            "ba0db6fccf992e543fc111dda7ccbb0170631f3b0f2232b8c378a12ed92f06683d6218f7a96414c0d729a50d7379"
        );
        let decrypted =
            decrypt_layered_chunk(&root_key, &base_nonce, &commitment, descriptor, &ciphertext)
                .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
}

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::aead::ChaCha20Poly1305 as HpkeAead;
use hpke::kdf::HkdfSha256 as HpkeKdf;
use hpke::kem::X25519HkdfSha256 as HpkeKem;
use hpke::{
    single_shot_open, single_shot_seal, Deserializable, Kem as HpkeKemTrait, OpModeR, OpModeS,
    Serializable,
};
use lvau_protocol::envelope_v3::{
    V3MutableEnvelope, V3MutableEnvelopeAuth, V3MutablePasswordSlot, V3MutablePayloadCore,
    V3MutableSlot, V3MutableX25519HpkeSlot, V3_KDF_ARGON2ID_V13, V3_MAGIC,
    V3_MUTABLE_ENVELOPE_REVISION, V3_MUTABLE_MAX_ENVELOPE_SIZE, V3_MUTABLE_MAX_RECIPIENTS,
    V3_MUTABLE_MAX_SLOTS, V3_MUTABLE_SLOT_HYBRID_X25519_MLKEM768, V3_MUTABLE_SLOT_MLKEM768,
    V3_MUTABLE_SLOT_PASSWORD, V3_MUTABLE_SLOT_X25519_HPKE, V3_VERSION,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use super::file::{self, decrypt_payload_frames, encrypt_payload_frames};
use super::mlkem;
use super::{derive_subkey, hybrid, V3KeyPurpose, V3SuiteId};
use crate::crypto::keys::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::output::persist_temp_path;
use crate::crypto::CryptoError;

const TAG_LEN: usize = 16;
const PASSWORD_WRAP_DOMAIN: &[u8] = b"Lvau v3 A4 password root wrapping\0";
const PASSWORD_WRAP_INFO: &[u8] = b"LV3-XC20P";
const PASSWORD_WRAP_INFO_LAYERED: &[u8] = b"LV3-AESGCMSIV-XC20P";
const PASSWORD_AAD_DOMAIN: &[u8] = b"Lvau v3 A4 password root AAD\0";
const PAYLOAD_BINDING_DOMAIN: &[u8] = b"Lvau v3 A4 payload binding\0";
const SLOT_CONTEXT_DOMAIN: &[u8] = b"Lvau v3 A4 slot context\0";
const HEADER_KEY_DOMAIN: &[u8] = b"Lvau v3 A4 header key\0";
const HEADER_KEY_INFO: &[u8] = b"Lvau v3 A4 header authenticator HMAC-SHA256\0";
const HEADER_MAC_DOMAIN: &[u8] = b"Lvau v3 A4 envelope authenticator\0";
const X25519_KEY_ID_DOMAIN: &[u8] = b"Lvau v3 A4 recipient key ID\0";
const HPKE_INFO_DOMAIN: &[u8] = b"Lvau v3 A4 X25519 HPKE info\0";
const HPKE_AAD_DOMAIN: &[u8] = b"Lvau v3 A4 X25519 HPKE AAD\0";
const HPKE_KEM_ID: u16 = 0x0020;
const HPKE_KDF_ID: u16 = 0x0001;
const HPKE_AEAD_ID: u16 = 0x0003;
const ROOT_KEY_LEN: usize = 32;
const WRAPPED_ROOT_KEY_LEN: usize = ROOT_KEY_LEN + TAG_LEN;

type HmacSha256 = Hmac<Sha256>;
type HpkePublicKey = <HpkeKem as HpkeKemTrait>::PublicKey;
type HpkePrivateKey = <HpkeKem as HpkeKemTrait>::PrivateKey;
type HpkeEncappedKey = <HpkeKem as HpkeKemTrait>::EncappedKey;

#[derive(Debug, Clone)]
pub struct V3MutableFileInfo {
    pub envelope: V3MutableEnvelope,
    pub password_kdf_costs: Option<(u32, u32, u32)>,
}

fn payload_core(envelope: &V3MutableEnvelope) -> V3MutablePayloadCore<'_> {
    V3MutablePayloadCore {
        magic: &envelope.magic,
        version: envelope.version,
        envelope_revision: envelope.envelope_revision,
        payload_suite_id: envelope.payload_suite_id,
        payload_base_nonce: &envelope.payload_base_nonce,
        plaintext_len: envelope.plaintext_len,
    }
}

pub(super) fn slot_order(slot: &V3MutableSlot) -> (u8, [u8; 32]) {
    match slot {
        V3MutableSlot::Password(_) => (V3_MUTABLE_SLOT_PASSWORD, [0; 32]),
        V3MutableSlot::X25519Hpke(slot) => (V3_MUTABLE_SLOT_X25519_HPKE, slot.key_id),
        V3MutableSlot::MlKem768(slot) => (V3_MUTABLE_SLOT_MLKEM768, slot.key_id),
        V3MutableSlot::HybridX25519MlKem768(slot) => {
            (V3_MUTABLE_SLOT_HYBRID_X25519_MLKEM768, slot.key_id)
        }
    }
}

pub(super) fn validate_envelope(envelope: &V3MutableEnvelope) -> Result<(), CryptoError> {
    if envelope.magic != V3_MAGIC
        || envelope.version != V3_VERSION
        || envelope.envelope_revision != V3_MUTABLE_ENVELOPE_REVISION
    {
        return Err(CryptoError::Validation("Unsupported v3 mutable envelope"));
    }
    if file::suite_from_id(envelope.payload_suite_id).is_err() {
        return Err(CryptoError::Validation("Unsupported v3 payload suite"));
    }
    if envelope.slots.is_empty() || envelope.slots.len() > V3_MUTABLE_MAX_SLOTS {
        return Err(CryptoError::Validation(
            "v3 recipient slot count is invalid",
        ));
    }

    let mut passwords = 0;
    let mut recipients = 0;
    let mut previous = None;
    for slot in &envelope.slots {
        match slot {
            V3MutableSlot::Password(slot) => {
                passwords += 1;
                if slot.kdf_id != V3_KDF_ARGON2ID_V13 {
                    return Err(CryptoError::Validation("Unsupported v3 password KDF"));
                }
                file::profile_costs(slot.profile_id)?;
            }
            V3MutableSlot::X25519Hpke(slot) => {
                recipients += 1;
                if !super::hpke_file::is_canonical_x25519(&slot.enc) {
                    return Err(CryptoError::Validation("Invalid v3 HPKE encapsulated key"));
                }
            }
            V3MutableSlot::MlKem768(_) => recipients += 1,
            V3MutableSlot::HybridX25519MlKem768(slot) => {
                recipients += 1;
                if !super::hpke_file::is_canonical_x25519(&slot.x25519.enc) {
                    return Err(CryptoError::Validation("Invalid v3 HPKE encapsulated key"));
                }
            }
        }

        let order = slot_order(slot);
        if previous.is_some_and(|previous| order <= previous) {
            return Err(CryptoError::Validation(
                "v3 slots are duplicated or not canonically ordered",
            ));
        }
        previous = Some(order);
    }
    if passwords > 1 || recipients > V3_MUTABLE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 recipient slot count is invalid",
        ));
    }
    Ok(())
}

pub(super) fn encode_envelope(envelope: &V3MutableEnvelope) -> Result<Vec<u8>, CryptoError> {
    validate_envelope(envelope)?;
    let bytes = postcard::to_allocvec(envelope)?;
    if bytes.is_empty() || bytes.len() > V3_MUTABLE_MAX_ENVELOPE_SIZE {
        return Err(CryptoError::Validation(
            "v3 mutable envelope size is invalid",
        ));
    }
    Ok(bytes)
}

pub(super) fn read_envelope(
    reader: &mut dyn Read,
) -> Result<(V3MutableEnvelope, Vec<u8>), CryptoError> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if !(6..=V3_MUTABLE_MAX_ENVELOPE_SIZE).contains(&length) {
        return Err(CryptoError::Validation(
            "v3 mutable envelope size is invalid",
        ));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let (envelope, trailing) = postcard::take_from_bytes::<V3MutableEnvelope>(&bytes)?;
    if !trailing.is_empty() || postcard::to_allocvec(&envelope)? != bytes {
        return Err(CryptoError::Validation(
            "v3 mutable envelope encoding is not canonical",
        ));
    }
    validate_envelope(&envelope)?;
    Ok((envelope, bytes))
}

/// Resolve the payload suite of a validated A4 envelope.
pub(super) fn envelope_suite(envelope: &V3MutableEnvelope) -> Result<V3SuiteId, CryptoError> {
    file::suite_from_id(envelope.payload_suite_id)
}

fn payload_binding(
    root_key: &[u8; 32],
    envelope: &V3MutableEnvelope,
) -> Result<[u8; 32], CryptoError> {
    let core = postcard::to_allocvec(&payload_core(envelope))?;
    let subkey = derive_subkey(
        root_key,
        envelope_suite(envelope)?,
        V3KeyPurpose::EnvelopeCommitment,
    )?;
    let hk = Hkdf::<Sha256>::new(Some(PAYLOAD_BINDING_DOMAIN), &*subkey);
    let mut binding = [0; 32];
    hk.expand(&core, &mut binding)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(binding)
}

pub(super) fn slot_context(envelope: &V3MutableEnvelope) -> Result<[u8; 32], CryptoError> {
    let core = postcard::to_allocvec(&payload_core(envelope))?;
    let mut hash = Sha256::new();
    hash.update(SLOT_CONTEXT_DOMAIN);
    hash.update(core);
    hash.update(envelope.payload_binding);
    Ok(hash.finalize().into())
}

fn auth_data(envelope: &V3MutableEnvelope) -> V3MutableEnvelopeAuth<'_> {
    V3MutableEnvelopeAuth {
        magic: &envelope.magic,
        version: envelope.version,
        envelope_revision: envelope.envelope_revision,
        payload_suite_id: envelope.payload_suite_id,
        payload_base_nonce: &envelope.payload_base_nonce,
        plaintext_len: envelope.plaintext_len,
        payload_binding: &envelope.payload_binding,
        slots: &envelope.slots,
    }
}

fn header_authenticator(
    root_key: &[u8; 32],
    envelope: &V3MutableEnvelope,
) -> Result<[u8; 32], CryptoError> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(HEADER_KEY_DOMAIN), root_key)
        .expand(HEADER_KEY_INFO, &mut *key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&*key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    mac.update(HEADER_MAC_DOMAIN);
    mac.update(&postcard::to_allocvec(&auth_data(envelope))?);
    Ok(mac.finalize().into_bytes().into())
}

pub(super) fn seal_header(
    root_key: &[u8; 32],
    envelope: &mut V3MutableEnvelope,
) -> Result<(), CryptoError> {
    validate_envelope(envelope)?;
    envelope.header_authenticator = header_authenticator(root_key, envelope)?;
    Ok(())
}

pub(super) fn verify_header(
    root_key: &[u8; 32],
    envelope: &V3MutableEnvelope,
) -> Result<(), CryptoError> {
    validate_envelope(envelope)?;
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(HEADER_KEY_DOMAIN), root_key)
        .expand(HEADER_KEY_INFO, &mut *key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&*key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    mac.update(HEADER_MAC_DOMAIN);
    mac.update(
        &postcard::to_allocvec(&auth_data(envelope)).map_err(|_| CryptoError::DecryptionFailed)?,
    );
    mac.verify_slice(&envelope.header_authenticator)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[derive(Serialize)]
struct PasswordWrapAad<'a> {
    magic: &'a [u8; 4],
    version: u16,
    envelope_revision: u8,
    payload_suite_id: u8,
    payload_base_nonce: &'a [u8; 24],
    plaintext_len: u64,
    payload_binding: &'a [u8; 32],
    slot_type_id: u8,
    profile_id: u8,
    kdf_id: u8,
    salt: &'a [u8; 16],
    wrapping_nonce: &'a [u8; 24],
}

fn password_wrap_aad(
    envelope: &V3MutableEnvelope,
    profile_id: u8,
    kdf_id: u8,
    salt: &[u8; 16],
    wrapping_nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let fields = PasswordWrapAad {
        magic: &envelope.magic,
        version: envelope.version,
        envelope_revision: envelope.envelope_revision,
        payload_suite_id: envelope.payload_suite_id,
        payload_base_nonce: &envelope.payload_base_nonce,
        plaintext_len: envelope.plaintext_len,
        payload_binding: &envelope.payload_binding,
        slot_type_id: V3_MUTABLE_SLOT_PASSWORD,
        profile_id,
        kdf_id,
        salt,
        wrapping_nonce,
    };
    let mut aad = Vec::from(PASSWORD_AAD_DOMAIN);
    aad.extend_from_slice(&postcard::to_allocvec(&fields)?);
    Ok(aad)
}

/// Wrap-key HKDF info for an A4 password slot, qualified by payload suite.
///
/// Suite-1 files keep the historical `LV3-XC20P` info byte-for-byte; only new
/// layered files use the layered info. Slot AAD binds the suite either way.
fn password_wrap_info(envelope: &V3MutableEnvelope) -> Result<&'static [u8], CryptoError> {
    match envelope_suite(envelope)? {
        V3SuiteId::XChaCha20Poly1305 => Ok(PASSWORD_WRAP_INFO),
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => Ok(PASSWORD_WRAP_INFO_LAYERED),
    }
}

pub(super) fn wrap_password_slot(
    envelope: &V3MutableEnvelope,
    root_key: &[u8; 32],
    password: &SecretString,
    profile_id: u8,
) -> Result<V3MutablePasswordSlot, CryptoError> {
    if password.expose_secret().is_empty() {
        return Err(CryptoError::Validation("Password must not be empty"));
    }
    let costs = file::profile_costs(profile_id)?;
    let mut salt = [0; 16];
    let mut wrapping_nonce = [0; 24];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut wrapping_nonce);
    let master_key = file::derive_master_key(password, &salt, costs)?;
    let mut wrapping_key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(PASSWORD_WRAP_DOMAIN), &*master_key)
        .expand(password_wrap_info(envelope)?, &mut *wrapping_key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let aad = password_wrap_aad(
        envelope,
        profile_id,
        V3_KDF_ARGON2ID_V13,
        &salt,
        &wrapping_nonce,
    )?;
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let wrapped: [u8; WRAPPED_ROOT_KEY_LEN] = cipher
        .encrypt(
            &XNonce::from(wrapping_nonce),
            Payload {
                msg: root_key,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(V3MutablePasswordSlot {
        profile_id,
        kdf_id: V3_KDF_ARGON2ID_V13,
        salt,
        wrapping_nonce,
        encrypted_file_root_key: wrapped,
    })
}

pub(super) fn unwrap_password_slot(
    envelope: &V3MutableEnvelope,
    slot: &V3MutablePasswordSlot,
    password: &SecretString,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if slot.kdf_id != V3_KDF_ARGON2ID_V13 || password.expose_secret().is_empty() {
        return Err(CryptoError::DecryptionFailed);
    }
    let costs = file::profile_costs(slot.profile_id).map_err(|_| CryptoError::DecryptionFailed)?;
    let master_key = file::derive_master_key(password, &slot.salt, costs)?;
    let mut wrapping_key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(PASSWORD_WRAP_DOMAIN), &*master_key)
        .expand(
            password_wrap_info(envelope).map_err(|_| CryptoError::DecryptionFailed)?,
            &mut *wrapping_key,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let aad = password_wrap_aad(
        envelope,
        slot.profile_id,
        slot.kdf_id,
        &slot.salt,
        &slot.wrapping_nonce,
    )
    .map_err(|_| CryptoError::DecryptionFailed)?;
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(slot.wrapping_nonce),
                Payload {
                    msg: &slot.encrypted_file_root_key,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    if plaintext.len() != ROOT_KEY_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut root_key = Zeroizing::new([0; ROOT_KEY_LEN]);
    root_key.copy_from_slice(&plaintext);
    Ok(root_key)
}

pub(super) fn x25519_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(X25519_KEY_ID_DOMAIN);
    hash.update([V3_MUTABLE_SLOT_X25519_HPKE]);
    hash.update(HPKE_KEM_ID.to_be_bytes());
    hash.update(HPKE_KDF_ID.to_be_bytes());
    hash.update(HPKE_AEAD_ID.to_be_bytes());
    hash.update(public_key);
    hash.finalize().into()
}

fn hpke_context(context: &[u8; 32], key_id: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut info = Vec::with_capacity(HPKE_INFO_DOMAIN.len() + 71);
    info.extend_from_slice(HPKE_INFO_DOMAIN);
    info.extend_from_slice(context);
    info.push(V3_MUTABLE_SLOT_X25519_HPKE);
    info.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
    info.extend_from_slice(&HPKE_KDF_ID.to_be_bytes());
    info.extend_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    info.extend_from_slice(key_id);

    let mut aad = Vec::with_capacity(HPKE_AAD_DOMAIN.len() + 71);
    aad.extend_from_slice(HPKE_AAD_DOMAIN);
    aad.extend_from_slice(context);
    aad.push(V3_MUTABLE_SLOT_X25519_HPKE);
    aad.extend_from_slice(&HPKE_KEM_ID.to_be_bytes());
    aad.extend_from_slice(&HPKE_KDF_ID.to_be_bytes());
    aad.extend_from_slice(&HPKE_AEAD_ID.to_be_bytes());
    aad.extend_from_slice(key_id);
    (info, aad)
}

pub(super) fn wrap_x25519_root_key(
    root_key: &[u8; ROOT_KEY_LEN],
    public_key_bytes: &[u8; 32],
    context: &[u8; 32],
) -> Result<V3MutableX25519HpkeSlot, CryptoError> {
    if !super::hpke_file::is_canonical_x25519(public_key_bytes) {
        return Err(CryptoError::Validation(
            "Recipient X25519 public key is not canonical",
        ));
    }
    let public_key = HpkePublicKey::from_bytes(public_key_bytes)
        .map_err(|_| CryptoError::Validation("Invalid recipient X25519 public key"))?;
    let key_id = x25519_key_id(public_key_bytes);
    let (info, aad) = hpke_context(context, &key_id);
    let (enc, wrapped) = single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        &public_key,
        &info,
        root_key,
        &aad,
    )
    .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut enc_bytes = [0; 32];
    enc.write_exact(&mut enc_bytes);
    let encrypted_file_root_key: [u8; WRAPPED_ROOT_KEY_LEN] = wrapped
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(V3MutableX25519HpkeSlot {
        key_id,
        enc: enc_bytes,
        encrypted_file_root_key,
    })
}

pub(super) fn unwrap_x25519_root_key(
    private_key: &HybridPrivateKey,
    slot: &V3MutableX25519HpkeSlot,
    context: &[u8; 32],
) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, CryptoError> {
    if !super::hpke_file::is_canonical_x25519(&slot.enc) {
        return Err(CryptoError::DecryptionFailed);
    }
    let private_bytes = Zeroizing::new(private_key.x25519.to_bytes());
    let hpke_private =
        HpkePrivateKey::from_bytes(&*private_bytes).map_err(|_| CryptoError::DecryptionFailed)?;
    let hpke_public = HpkeKem::sk_to_pk(&hpke_private);
    let mut public_bytes = [0; 32];
    hpke_public.write_exact(&mut public_bytes);
    if !super::hpke_file::is_canonical_x25519(&public_bytes)
        || x25519_key_id(&public_bytes) != slot.key_id
    {
        return Err(CryptoError::DecryptionFailed);
    }
    let enc = HpkeEncappedKey::from_bytes(&slot.enc).map_err(|_| CryptoError::DecryptionFailed)?;
    let (info, aad) = hpke_context(context, &slot.key_id);
    let plaintext = Zeroizing::new(
        single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &hpke_private,
            &enc,
            &info,
            &slot.encrypted_file_root_key,
            &aad,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    if plaintext.len() != ROOT_KEY_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut root_key = Zeroizing::new([0; ROOT_KEY_LEN]);
    root_key.copy_from_slice(&plaintext);
    Ok(root_key)
}

pub(super) fn unwrap_for_private_key(
    envelope: &V3MutableEnvelope,
    private_key: &HybridPrivateKey,
) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, CryptoError> {
    let context = slot_context(envelope)?;
    let mut public_bytes = [0; 32];
    let hpke_private = Zeroizing::new(private_key.x25519.to_bytes());
    let imported =
        HpkePrivateKey::from_bytes(&*hpke_private).map_err(|_| CryptoError::DecryptionFailed)?;
    let public = HpkeKem::sk_to_pk(&imported);
    public.write_exact(&mut public_bytes);
    let x25519_id = x25519_key_id(&public_bytes);
    if let Some(V3MutableSlot::X25519Hpke(slot)) = envelope
        .slots
        .iter()
        .find(|slot| matches!(slot, V3MutableSlot::X25519Hpke(slot) if slot.key_id == x25519_id))
    {
        return unwrap_x25519_root_key(private_key, slot, &context);
    }

    let mlkem_id = mlkem::recipient_key_id(private_key.mlkem.encapsulation_key());
    if let Some(V3MutableSlot::MlKem768(slot)) = envelope
        .slots
        .iter()
        .find(|slot| matches!(slot, V3MutableSlot::MlKem768(slot) if slot.key_id == mlkem_id))
    {
        return mlkem::unwrap_root_key(&private_key.mlkem, slot, &context);
    }
    let hybrid_id = hybrid::recipient_key_id(&public_bytes, private_key.mlkem.encapsulation_key());
    if let Some(V3MutableSlot::HybridX25519MlKem768(slot)) = envelope
        .slots
        .iter()
        .find(
            |slot| matches!(slot, V3MutableSlot::HybridX25519MlKem768(slot) if slot.key_id == hybrid_id),
        )
    {
        return hybrid::unwrap_root_key(private_key, slot, &context);
    }
    Err(CryptoError::DecryptionFailed)
}

pub(super) fn unwrap_for_password(
    envelope: &V3MutableEnvelope,
    password: &SecretString,
) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, CryptoError> {
    let slot = envelope
        .slots
        .iter()
        .find_map(|slot| match slot {
            V3MutableSlot::Password(slot) => Some(slot),
            _ => None,
        })
        .ok_or(CryptoError::DecryptionFailed)?;
    unwrap_password_slot(envelope, slot, password)
}

pub(super) fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(super) fn persist(
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

pub(super) fn write_length_and_envelope(
    output: &mut NamedTempFile,
    bytes: &[u8],
) -> Result<(), CryptoError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| CryptoError::Validation("v3 mutable envelope size is invalid"))?;
    output.write_all(&length.to_le_bytes())?;
    output.write_all(bytes)?;
    Ok(())
}

pub fn encrypt_file_mlkem(
    input_path: &Path,
    output_path: &Path,
    recipients: &[HybridPublicKey],
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    encrypt_file_mlkem_with_suite(
        input_path,
        output_path,
        recipients,
        V3SuiteId::XChaCha20Poly1305,
        replace_existing,
        progress,
    )
}

/// Create an A4 ML-KEM-768 envelope with an explicit payload suite.
///
/// The default stays single-layer `LV3-XC20P`; pass the layered suite
/// explicitly to opt in.
pub fn encrypt_file_mlkem_with_suite(
    input_path: &Path,
    output_path: &Path,
    recipients: &[HybridPublicKey],
    suite: V3SuiteId,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    if recipients.is_empty() || recipients.len() > V3_MUTABLE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 ML-KEM recipient count is invalid",
        ));
    }
    let mut keyed_recipients = recipients
        .iter()
        .map(|recipient| (mlkem::recipient_key_id(&recipient.mlkem), &recipient.mlkem))
        .collect::<Vec<_>>();
    keyed_recipients.sort_by_key(|(key_id, _)| *key_id);
    if keyed_recipients
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(CryptoError::Validation("Duplicate v3 ML-KEM recipient"));
    }

    let mut input = File::open(input_path)?;
    let plaintext_len = input.metadata()?.len();
    let mut rng = OsRng;
    let mut root_key = Zeroizing::new([0; ROOT_KEY_LEN]);
    rng.fill_bytes(&mut *root_key);
    let mut payload_base_nonce = [0; 24];
    rng.fill_bytes(&mut payload_base_nonce);
    let mut envelope = V3MutableEnvelope {
        magic: V3_MAGIC,
        version: V3_VERSION,
        envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
        payload_suite_id: file::suite_wire_id(suite),
        payload_base_nonce,
        plaintext_len,
        payload_binding: [0; 32],
        slots: Vec::with_capacity(keyed_recipients.len()),
        header_authenticator: [0; 32],
    };
    envelope.payload_binding = payload_binding(&root_key, &envelope)?;
    let context = slot_context(&envelope)?;
    for (_, public_key) in keyed_recipients {
        envelope
            .slots
            .push(V3MutableSlot::MlKem768(mlkem::wrap_root_key(
                &root_key, public_key, &context,
            )?));
    }
    envelope.slots.sort_by_key(slot_order);
    seal_header(&root_key, &mut envelope)?;
    let envelope_bytes = encode_envelope(&envelope)?;
    let commitment = envelope.payload_binding;

    let mut output = NamedTempFile::new_in(parent_directory(output_path))?;
    write_length_and_envelope(&mut output, &envelope_bytes)?;
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
    persist(output, output_path, replace_existing)
}

pub fn encrypt_file_hybrid(
    input_path: &Path,
    output_path: &Path,
    recipients: &[HybridPublicKey],
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    encrypt_file_hybrid_with_suite(
        input_path,
        output_path,
        recipients,
        V3SuiteId::XChaCha20Poly1305,
        replace_existing,
        progress,
    )
}

/// Create an A4 dual-wrap hybrid envelope with an explicit payload suite.
///
/// The default stays single-layer `LV3-XC20P`; pass the layered suite
/// explicitly to opt in.
pub fn encrypt_file_hybrid_with_suite(
    input_path: &Path,
    output_path: &Path,
    recipients: &[HybridPublicKey],
    suite: V3SuiteId,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    if recipients.is_empty() || recipients.len() > V3_MUTABLE_MAX_RECIPIENTS {
        return Err(CryptoError::Validation(
            "v3 hybrid recipient count is invalid",
        ));
    }
    let mut keyed_recipients = recipients
        .iter()
        .map(|recipient| {
            (
                hybrid::recipient_key_id(&recipient.x25519.to_bytes(), &recipient.mlkem),
                recipient,
            )
        })
        .collect::<Vec<_>>();
    keyed_recipients.sort_by_key(|(key_id, _)| *key_id);
    if keyed_recipients
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(CryptoError::Validation("Duplicate v3 hybrid recipient"));
    }

    let mut input = File::open(input_path)?;
    let plaintext_len = input.metadata()?.len();
    let mut rng = OsRng;
    let mut root_key = Zeroizing::new([0; ROOT_KEY_LEN]);
    rng.fill_bytes(&mut *root_key);
    let mut payload_base_nonce = [0; 24];
    rng.fill_bytes(&mut payload_base_nonce);
    let mut envelope = V3MutableEnvelope {
        magic: V3_MAGIC,
        version: V3_VERSION,
        envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
        payload_suite_id: file::suite_wire_id(suite),
        payload_base_nonce,
        plaintext_len,
        payload_binding: [0; 32],
        slots: Vec::with_capacity(keyed_recipients.len()),
        header_authenticator: [0; 32],
    };
    envelope.payload_binding = payload_binding(&root_key, &envelope)?;
    let context = slot_context(&envelope)?;
    for (_, recipient) in keyed_recipients {
        envelope
            .slots
            .push(V3MutableSlot::HybridX25519MlKem768(hybrid::wrap_root_key(
                &root_key, recipient, &context,
            )?));
    }
    envelope.slots.sort_by_key(slot_order);
    seal_header(&root_key, &mut envelope)?;
    let envelope_bytes = encode_envelope(&envelope)?;
    let commitment = envelope.payload_binding;

    let mut output = NamedTempFile::new_in(parent_directory(output_path))?;
    write_length_and_envelope(&mut output, &envelope_bytes)?;
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
    persist(output, output_path, replace_existing)
}

pub(super) fn read_file(
    input_path: &Path,
) -> Result<(File, V3MutableEnvelope, Vec<u8>), CryptoError> {
    let mut input = File::open(input_path)?;
    let (envelope, bytes) = read_envelope(&mut input)?;
    Ok((input, envelope, bytes))
}

fn decrypt_to_writer(
    input: &mut File,
    envelope: &V3MutableEnvelope,
    envelope_bytes: &[u8],
    root_key: &[u8; ROOT_KEY_LEN],
    writer: &mut dyn Write,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    verify_header(root_key, envelope)?;
    decrypt_payload_frames(
        input,
        writer,
        envelope.plaintext_len,
        &envelope.payload_base_nonce,
        root_key,
        &envelope.payload_binding,
        envelope_suite(envelope)?,
        progress,
    )?;
    let _ = envelope_bytes;
    Ok(())
}

pub fn decrypt_file_password(
    input_path: &Path,
    output_path: &Path,
    password: SecretString,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let (mut input, envelope, envelope_bytes) = read_file(input_path)?;
    let root_key = unwrap_for_password(&envelope, &password)?;
    let mut output = NamedTempFile::new_in(parent_directory(output_path))?;
    decrypt_to_writer(
        &mut input,
        &envelope,
        &envelope_bytes,
        &root_key,
        &mut output,
        progress,
    )?;
    output.as_file().sync_all()?;
    persist(output, output_path, replace_existing)
}

pub fn decrypt_file_keypair(
    input_path: &Path,
    output_path: &Path,
    private_key: &HybridPrivateKey,
    replace_existing: bool,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let (mut input, envelope, envelope_bytes) = read_file(input_path)?;
    let root_key = unwrap_for_private_key(&envelope, private_key)?;
    let mut output = NamedTempFile::new_in(parent_directory(output_path))?;
    decrypt_to_writer(
        &mut input,
        &envelope,
        &envelope_bytes,
        &root_key,
        &mut output,
        progress,
    )?;
    output.as_file().sync_all()?;
    persist(output, output_path, replace_existing)
}

pub fn verify_file_password(
    input_path: &Path,
    password: SecretString,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let (mut input, envelope, envelope_bytes) = read_file(input_path)?;
    let root_key = unwrap_for_password(&envelope, &password)?;
    decrypt_to_writer(
        &mut input,
        &envelope,
        &envelope_bytes,
        &root_key,
        &mut io::sink(),
        progress,
    )
}

pub fn verify_file_keypair(
    input_path: &Path,
    private_key: &HybridPrivateKey,
    progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), CryptoError> {
    let (mut input, envelope, envelope_bytes) = read_file(input_path)?;
    let root_key = unwrap_for_private_key(&envelope, private_key)?;
    decrypt_to_writer(
        &mut input,
        &envelope,
        &envelope_bytes,
        &root_key,
        &mut io::sink(),
        progress,
    )
}

pub fn inspect_file(input_path: &Path) -> Result<V3MutableFileInfo, CryptoError> {
    let (_, envelope, _) = read_file(input_path)?;
    let password_kdf_costs = envelope
        .slots
        .iter()
        .find_map(|slot| match slot {
            V3MutableSlot::Password(slot) => Some(slot.profile_id),
            _ => None,
        })
        .map(file::profile_costs)
        .transpose()?;
    Ok(V3MutableFileInfo {
        envelope,
        password_kdf_costs,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use lvau_protocol::envelope_v3::{
        V3MutableMlKem768Slot, V3MutablePasswordSlot, V3_MLKEM768_CIPHERTEXT_SIZE,
        V3_SUITE_XCHACHA20_POLY1305,
    };

    use super::*;

    #[test]
    fn mutable_envelope_rejects_noncanonical_postcard_varint() {
        let envelope = V3MutableEnvelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
            payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
            payload_base_nonce: [0; 24],
            plaintext_len: 0,
            payload_binding: [0; 32],
            slots: vec![V3MutableSlot::Password(V3MutablePasswordSlot {
                profile_id: 0,
                kdf_id: V3_KDF_ARGON2ID_V13,
                salt: [0; 16],
                wrapping_nonce: [0; 24],
                encrypted_file_root_key: [0; 48],
            })],
            header_authenticator: [0; 32],
        };
        let canonical = postcard::to_allocvec(&envelope).unwrap();
        assert_eq!(canonical[4], V3_VERSION as u8);

        let mut noncanonical = canonical;
        noncanonical[4] |= 0x80;
        noncanonical.insert(5, 0);
        let mut framed = (noncanonical.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&noncanonical);
        assert!(read_envelope(&mut Cursor::new(framed)).is_err());
    }

    #[test]
    fn mutable_envelope_binding_header_and_frame_fixed_vector() {
        let root_key = [0xa5; 32];
        let mut envelope = V3MutableEnvelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
            payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
            payload_base_nonce: [0x40; 24],
            plaintext_len: 6,
            payload_binding: [0; 32],
            slots: vec![V3MutableSlot::Password(V3MutablePasswordSlot {
                profile_id: 0,
                kdf_id: V3_KDF_ARGON2ID_V13,
                salt: [0x10; 16],
                wrapping_nonce: [0x20; 24],
                encrypted_file_root_key: [0x30; 48],
            })],
            header_authenticator: [0; 32],
        };
        envelope.payload_binding = payload_binding(&root_key, &envelope).unwrap();
        let context = slot_context(&envelope).unwrap();
        seal_header(&root_key, &mut envelope).unwrap();
        let envelope_bytes = encode_envelope(&envelope).unwrap();
        let frame = crate::crypto::suite::v3::encrypt_xchacha_chunk(
            &root_key,
            &envelope.payload_base_nonce,
            &envelope.payload_binding,
            crate::crypto::suite::v3::V3ChunkDescriptor::new(0, 6, true).unwrap(),
            b"vector",
        )
        .unwrap();
        assert_eq!(
            hex(&envelope.payload_binding),
            "6567498203eba28eface47d7b903372c3c6711e1800db616755e368758739284"
        );
        assert_eq!(
            hex(&context),
            "5d6cab7523280e9b1eabecca7992a7b2a929d30c891cd836d0b4079a6feac0f8"
        );
        assert_eq!(
            hex(&envelope.header_authenticator),
            "59e235b6cde019d907c7fa83fd200e7625bf3f41fa562f48d8859ff2ff00ae8d"
        );
        assert_eq!(hex(&envelope_bytes), "4c56415503a401404040404040404040404040404040404040404040404040066567498203eba28eface47d7b903372c3c6711e1800db616755e368758739284010000011010101010101010101010101010101020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303059e235b6cde019d907c7fa83fd200e7625bf3f41fa562f48d8859ff2ff00ae8d");
        assert_eq!(hex(&frame), "9adca79709a22534e1f0633a52ba31b8386198515b4a");
        verify_header(&root_key, &envelope).unwrap();

        let mut changed = envelope.clone();
        let V3MutableSlot::Password(slot) = &mut changed.slots[0] else {
            unreachable!();
        };
        slot.encrypted_file_root_key = [0x31; 48];
        assert!(verify_header(&root_key, &changed).is_err());
    }

    #[test]
    fn mutable_envelope_allows_password_plus_64_recipients_only() {
        let mut slots = vec![V3MutableSlot::Password(V3MutablePasswordSlot {
            profile_id: 0,
            kdf_id: V3_KDF_ARGON2ID_V13,
            salt: [1; 16],
            wrapping_nonce: [2; 24],
            encrypted_file_root_key: [3; 48],
        })];
        for key_id in 0..V3_MUTABLE_MAX_RECIPIENTS {
            let mut id = [0; 32];
            id[31] = key_id as u8;
            slots.push(V3MutableSlot::MlKem768(V3MutableMlKem768Slot {
                key_id: id,
                encapsulation_ciphertext: Box::new([4; V3_MLKEM768_CIPHERTEXT_SIZE]),
                wrapping_nonce: [5; 24],
                encrypted_file_root_key: [6; 48],
            }));
        }
        slots.sort_by_key(slot_order);
        let envelope = V3MutableEnvelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
            payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
            payload_base_nonce: [7; 24],
            plaintext_len: 0,
            payload_binding: [8; 32],
            slots,
            header_authenticator: [9; 32],
        };
        assert!(validate_envelope(&envelope).is_ok());
        assert!(encode_envelope(&envelope).is_ok());

        let mut too_many = envelope;
        let mut id = [0; 32];
        id[31] = 64;
        too_many
            .slots
            .push(V3MutableSlot::MlKem768(V3MutableMlKem768Slot {
                key_id: id,
                encapsulation_ciphertext: Box::new([4; V3_MLKEM768_CIPHERTEXT_SIZE]),
                wrapping_nonce: [5; 24],
                encrypted_file_root_key: [6; 48],
            }));
        too_many.slots.sort_by_key(slot_order);
        assert!(validate_envelope(&too_many).is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn layered_a4_mlkem_roundtrip_and_suite_relabelling_fails() {
        use std::fs;

        use tempfile::tempdir;

        use crate::crypto::keys::generate_keypair;

        let directory = tempdir().unwrap();
        let input = directory.path().join("input");
        let encrypted = directory.path().join("encrypted.lvau");
        let output = directory.path().join("output");
        fs::write(&input, b"layered A4 payload").unwrap();
        let (private, public) = generate_keypair();

        encrypt_file_mlkem_with_suite(
            &input,
            &encrypted,
            &[public],
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
            false,
            None,
        )
        .unwrap();
        let info = inspect_file(&encrypted).unwrap();
        assert_eq!(
            info.envelope.payload_suite_id,
            lvau_protocol::envelope_v3::V3_SUITE_AES256_GCM_SIV_XCHACHA20_POLY1305
        );
        verify_file_keypair(&encrypted, &private, None).unwrap();
        decrypt_file_keypair(&encrypted, &output, &private, false, None).unwrap();
        assert_eq!(fs::read(output).unwrap(), b"layered A4 payload");

        // Relabelling the suite breaks the header authenticator and the
        // suite-bound frame codecs; nothing verifies afterwards.
        let bytes = fs::read(&encrypted).unwrap();
        let envelope_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let (mut envelope, trailing) =
            postcard::take_from_bytes::<V3MutableEnvelope>(&bytes[4..4 + envelope_len]).unwrap();
        assert!(trailing.is_empty());
        envelope.payload_suite_id = lvau_protocol::envelope_v3::V3_SUITE_XCHACHA20_POLY1305;
        let encoded = postcard::to_allocvec(&envelope).unwrap();
        let mut damaged = (encoded.len() as u32).to_le_bytes().to_vec();
        damaged.extend_from_slice(&encoded);
        damaged.extend_from_slice(&bytes[4 + envelope_len..]);
        let relabelled = directory.path().join("relabelled.lvau");
        fs::write(&relabelled, damaged).unwrap();
        assert!(verify_file_keypair(&relabelled, &private, None).is_err());
    }

    #[test]
    fn hybrid_envelope_roundtrip_in_both_payload_suites() {
        use std::fs;

        use tempfile::tempdir;

        use crate::crypto::keys::generate_keypair;

        for suite in [
            V3SuiteId::XChaCha20Poly1305,
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
        ] {
            let directory = tempdir().unwrap();
            let input = directory.path().join("input");
            let encrypted = directory.path().join("encrypted.lvau");
            let output = directory.path().join("output");
            fs::write(&input, b"hybrid envelope payload").unwrap();
            let (private, public) = generate_keypair();
            let (wrong_private, _) = generate_keypair();

            encrypt_file_hybrid_with_suite(&input, &encrypted, &[public], suite, false, None)
                .unwrap();
            let info = inspect_file(&encrypted).unwrap();
            assert_eq!(info.envelope.payload_suite_id, file::suite_wire_id(suite));
            verify_file_keypair(&encrypted, &private, None).unwrap();
            assert!(verify_file_keypair(&encrypted, &wrong_private, None).is_err());
            decrypt_file_keypair(&encrypted, &output, &private, false, None).unwrap();
            assert_eq!(fs::read(output).unwrap(), b"hybrid envelope payload");
        }
    }
}

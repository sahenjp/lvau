//! Experimental dual-wrap X25519 + ML-KEM-768 recipient slots.
//!
//! The same file root key is wrapped independently for each component of the
//! recipient's hybrid public key, reusing the X25519-HPKE and ML-KEM-768 wrap
//! primitives with the shared A4 slot context. Either private component
//! recovers the root key.
//!
//! This is not a KEM combiner: breaking either component KEM exposes the file
//! root key. The construction stays experimental until its composition is
//! stable and independently reviewed.

use ml_kem::kem::KeyExport;
use ml_kem::EncapsulationKey768;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroizing;

use lvau_protocol::envelope_v3::{V3MutableHybridSlot, V3_MUTABLE_SLOT_HYBRID_X25519_MLKEM768};

use super::{hpke_file, mlkem, mutable_file};
use crate::crypto::keys::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::CryptoError;

const KEY_ID_DOMAIN: &[u8] = b"Lvau v3 A4 recipient key ID\0";

/// Algorithm-qualified key identifier binding both hybrid public components.
pub(super) fn recipient_key_id(
    x25519_public: &[u8; 32],
    mlkem_public: &EncapsulationKey768,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_ID_DOMAIN);
    hash.update([V3_MUTABLE_SLOT_HYBRID_X25519_MLKEM768]);
    hash.update(x25519_public);
    hash.update(mlkem_public.to_bytes());
    hash.finalize().into()
}

fn hybrid_key_id_for_private(private: &HybridPrivateKey) -> Result<[u8; 32], CryptoError> {
    let public_bytes = X25519PublicKey::from(&private.x25519).to_bytes();
    if !hpke_file::is_canonical_x25519(&public_bytes) {
        return Err(CryptoError::DecryptionFailed);
    }
    Ok(recipient_key_id(
        &public_bytes,
        private.mlkem.encapsulation_key(),
    ))
}

/// Wrap the file root key for both hybrid components under one hybrid slot.
pub(super) fn wrap_root_key(
    root: &[u8; 32],
    recipient: &HybridPublicKey,
    context: &[u8; 32],
) -> Result<V3MutableHybridSlot, CryptoError> {
    let x25519_public = recipient.x25519.to_bytes();
    let key_id = recipient_key_id(&x25519_public, &recipient.mlkem);
    let x25519 = mutable_file::wrap_x25519_root_key(root, &x25519_public, context)?;
    let mlkem = mlkem::wrap_root_key(root, &recipient.mlkem, context)?;
    debug_assert_eq!(x25519.key_id, mutable_file::x25519_key_id(&x25519_public));
    debug_assert_eq!(mlkem.key_id, mlkem::recipient_key_id(&recipient.mlkem));
    Ok(V3MutableHybridSlot {
        key_id,
        x25519,
        mlkem,
    })
}

/// Open a hybrid slot with either private component of the same hybrid key.
pub(super) fn unwrap_root_key(
    private: &HybridPrivateKey,
    slot: &V3MutableHybridSlot,
    context: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if hybrid_key_id_for_private(private)? != slot.key_id {
        return Err(CryptoError::DecryptionFailed);
    }
    if let Ok(root) = mutable_file::unwrap_x25519_root_key(private, &slot.x25519, context) {
        return Ok(root);
    }
    mlkem::unwrap_root_key(&private.mlkem, &slot.mlkem, context)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_keypair;

    #[test]
    fn hybrid_slot_opens_with_either_component() {
        let (private, public) = generate_keypair();
        let root = [0x42; 32];
        let context = [0xA4; 32];

        let slot = wrap_root_key(&root, &public, &context).unwrap();
        assert_eq!(*unwrap_root_key(&private, &slot, &context).unwrap(), root);

        // Tampering with either inner wrap keeps the other path usable, while
        // the file-level header authenticator still rejects the mutation.
        let mut broken_x = slot.clone();
        broken_x.x25519.encrypted_file_root_key[0] ^= 1;
        assert_eq!(
            *unwrap_root_key(&private, &broken_x, &context).unwrap(),
            root
        );

        let mut broken_m = slot.clone();
        broken_m.mlkem.encrypted_file_root_key[0] ^= 1;
        assert_eq!(
            *unwrap_root_key(&private, &broken_m, &context).unwrap(),
            root
        );

        let mut broken_both = slot.clone();
        broken_both.x25519.encrypted_file_root_key[0] ^= 1;
        broken_both.mlkem.encrypted_file_root_key[0] ^= 1;
        assert!(unwrap_root_key(&private, &broken_both, &context).is_err());
    }

    #[test]
    fn wrong_key_and_key_id_mutations_fail() {
        let (private, public) = generate_keypair();
        let (wrong_private, _) = generate_keypair();
        let context = [0x34; 32];
        let slot = wrap_root_key(&[0x12; 32], &public, &context).unwrap();

        assert!(unwrap_root_key(&wrong_private, &slot, &context).is_err());

        let mut changed = slot.clone();
        changed.key_id[0] ^= 1;
        assert!(unwrap_root_key(&private, &changed, &context).is_err());
    }

    #[test]
    fn hybrid_key_id_is_algorithm_and_key_separated() {
        let (_, public_a) = generate_keypair();
        let (_, public_b) = generate_keypair();
        let x25519_a = public_a.x25519.to_bytes();

        let hybrid = recipient_key_id(&x25519_a, &public_a.mlkem);
        assert_ne!(hybrid, recipient_key_id(&x25519_a, &public_b.mlkem));
        assert_ne!(hybrid, mlkem::recipient_key_id(&public_a.mlkem));
        assert_ne!(hybrid, mutable_file::x25519_key_id(&x25519_a));
    }
}

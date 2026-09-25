#![no_main]

use libfuzzer_sys::fuzz_target;
use lvau_core::crypto::suite::v3::file::{file_revision, is_v3_file, V3FileRevision};
use lvau_core::crypto::suite::v3::{file, hpke_file, mutable_file};
use lvau_protocol::envelope_v3::{
    V3HpkeEnvelope, V3HpkeRecipient, V3MutableEnvelope, V3MutableMlKem768Slot,
    V3MutablePasswordSlot, V3MutableSlot, V3MutableX25519HpkeSlot, V3_HPKE_MAX_ENVELOPE_SIZE,
    V3_MAGIC, V3_MUTABLE_ENVELOPE_REVISION, V3_MUTABLE_MAX_ENVELOPE_SIZE,
    V3_SUITE_XCHACHA20_POLY1305, V3_VERSION,
};
use std::sync::OnceLock;

macro_rules! check_canonical {
    ($type:ty, $input:expr) => {{
        let input: &[u8] = $input;
        if let Ok((envelope, trailing)) = postcard::take_from_bytes::<$type>(input) {
            if trailing.is_empty() {
                std::hint::black_box(postcard::to_allocvec(&envelope).unwrap());
            }
        }
    }};
}

fn seeds() -> &'static [Vec<u8>; 4] {
    static SEEDS: OnceLock<[Vec<u8>; 4]> = OnceLock::new();
    SEEDS.get_or_init(|| {
        let hpke = V3HpkeEnvelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            envelope_revision: 0xA3,
            payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
            payload_base_nonce: [1; 24],
            plaintext_len: 0,
            recipients: vec![V3HpkeRecipient {
                recipient_suite_id: 1,
                key_id: [2; 32],
                enc: [3; 32],
                encrypted_file_root_key: [4; 48],
            }],
        };
        let base = |slot| V3MutableEnvelope {
            magic: V3_MAGIC,
            version: V3_VERSION,
            envelope_revision: V3_MUTABLE_ENVELOPE_REVISION,
            payload_suite_id: V3_SUITE_XCHACHA20_POLY1305,
            payload_base_nonce: [5; 24],
            plaintext_len: 0,
            payload_binding: [6; 32],
            slots: vec![slot],
            header_authenticator: [7; 32],
        };
        let password = base(V3MutableSlot::Password(V3MutablePasswordSlot {
            profile_id: 0,
            kdf_id: 1,
            salt: [8; 16],
            wrapping_nonce: [9; 24],
            encrypted_file_root_key: [10; 48],
        }));
        let x25519 = base(V3MutableSlot::X25519Hpke(V3MutableX25519HpkeSlot {
            key_id: [11; 32],
            enc: [12; 32],
            encrypted_file_root_key: [13; 48],
        }));
        let mlkem = base(V3MutableSlot::MlKem768(V3MutableMlKem768Slot {
            key_id: [14; 32],
            encapsulation_ciphertext: Box::new([15; 1088]),
            wrapping_nonce: [16; 24],
            encrypted_file_root_key: [17; 48],
        }));
        [
            postcard::to_allocvec(&hpke).unwrap(),
            postcard::to_allocvec(&password).unwrap(),
            postcard::to_allocvec(&x25519).unwrap(),
            postcard::to_allocvec(&mlkem).unwrap(),
        ]
    })
}

fn mutate_seed(seed: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mutated = seed.to_vec();
    for bytes in data.chunks(3) {
        let low = bytes[0] as usize;
        let high = bytes.get(1).copied().unwrap_or(0) as usize;
        let index = (low | (high << 8)) % mutated.len();
        mutated[index] ^= bytes.get(2).copied().unwrap_or(1);
    }
    mutated
}

fn inspect_file(bytes: &[u8]) {
    static DIRECTORY: OnceLock<Option<tempfile::TempDir>> = OnceLock::new();
    let Some(directory) = DIRECTORY.get_or_init(|| tempfile::tempdir().ok()) else {
        return;
    };
    let path = directory.path().join("input.lvau");
    if std::fs::write(&path, bytes).is_err() || !is_v3_file(&path).unwrap_or(false) {
        return;
    }
    match file_revision(&path) {
        Ok(V3FileRevision::LegacyPassword) => {
            let _ = file::inspect_file(&path);
        }
        Ok(V3FileRevision::HpkeRecipients) => {
            let _ = hpke_file::inspect_file(&path);
        }
        Ok(V3FileRevision::MutableSlots) => {
            let _ = mutable_file::inspect_file(&path);
        }
        Err(_) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > V3_MUTABLE_MAX_ENVELOPE_SIZE {
        return;
    }

    if data.len() <= V3_HPKE_MAX_ENVELOPE_SIZE {
        check_canonical!(V3HpkeEnvelope, data);
    }
    check_canonical!(V3MutableEnvelope, data);
    inspect_file(data);

    if data.len() <= V3_MUTABLE_MAX_ENVELOPE_SIZE {
        let mut framed = (data.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(data);
        inspect_file(&framed);
    }

    for (index, seed) in seeds().iter().enumerate() {
        match index {
            0 if seed.len() <= V3_HPKE_MAX_ENVELOPE_SIZE => {
                check_canonical!(V3HpkeEnvelope, seed)
            }
            _ => check_canonical!(V3MutableEnvelope, seed),
        }
        let mutated = mutate_seed(seed, data);
        match index {
            0 if mutated.len() <= V3_HPKE_MAX_ENVELOPE_SIZE => {
                check_canonical!(V3HpkeEnvelope, &mutated)
            }
            _ => check_canonical!(V3MutableEnvelope, &mutated),
        }
        let mut framed = (mutated.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&mutated);
        inspect_file(&framed);
    }
});

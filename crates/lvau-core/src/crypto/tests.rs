use super::keys::generate_keypair;
use super::parallel::CHUNK_SIZE;
use super::*;
use base64::Engine;
use lvau_protocol::envelope::Envelope;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::env::temp_dir;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_path(name: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    temp_dir().join(format!("lvau-test-{}-{}-{}", std::process::id(), id, name))
}

fn roundtrip_bytes(name: &str, bytes: &[u8]) {
    let input = unique_path(&format!("{name}.input"));
    let enc = unique_path(&format!("{name}.lvau"));
    let dec = unique_path(&format!("{name}.output"));
    let password = SecretString::from("correct horse battery staple".to_string());

    fs::write(&input, bytes).unwrap();
    let original_hash = Sha256::digest(bytes);

    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();
    decrypt_file_password(&enc, &dec, password, None, None).unwrap();

    let decrypted = fs::read(&dec).unwrap();
    assert_eq!(Sha256::digest(&decrypted), original_hash);
    assert_eq!(decrypted, bytes);
}

#[test]
fn encryption_rejects_input_length_changes() {
    for actual in [b"abc".as_slice(), b"abcde".as_slice()] {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("output.lvau");
        let envelope = Envelope {
            header: EnvelopeHeader {
                magic: MAGIC_REAL,
                version: CURRENT_VERSION,
                profile: SecurityProfile::Fast,
                algorithm: AlgorithmId::XChaCha20Poly1305,
                kdf: None,
                recipients: Vec::new(),
            },
            plaintext_len: 4,
            nonce: [0; 24],
            secondary_nonce: None,
            aad_hash: [0; 32],
            metadata: Vec::new(),
            content_type: None,
            signature: None,
            public_label: None,
            approvals: Vec::new(),
            release_metadata: None,
            policy_overridden: false,
            recovery_metadata: None,
        };
        let hk = Hkdf::<Sha256>::new(None, &[0; 32]);
        let mut reader = std::io::Cursor::new(actual);

        let result = write_envelope_and_payload(
            &output,
            &envelope,
            &AlgorithmId::XChaCha20Poly1305,
            &hk,
            &mut reader,
            None,
            false,
        );

        assert!(matches!(result, Err(CryptoError::Validation(_))));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn encryption_no_clobber_closes_persistence_race_and_overwrite_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let output = dir.path().join("output.lvau");
    let decrypted = dir.path().join("decrypted.bin");
    let plaintext = b"authenticated plaintext";
    let competing = b"competing output";
    let password = SecretString::from("password123".to_string());

    fs::write(&input, plaintext).unwrap();
    let mut created_competing_output = false;
    let mut create_competing_output = |_: u64| {
        if !created_competing_output {
            fs::write(&output, competing).unwrap();
            created_competing_output = true;
        }
    };

    let result = encrypt_file_password(
        &input,
        &output,
        password.clone(),
        None,
        SecurityProfile::Fast,
        Some(&mut create_competing_output),
        None,
        false,
    );

    assert!(created_competing_output);
    assert!(matches!(result, Err(CryptoError::OutputExists)));
    assert_eq!(fs::read(&output).unwrap(), competing);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);

    encrypt_file_password_with_overwrite(
        &input,
        &output,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    decrypt_file_password(&output, &decrypted, password, None, None).unwrap();
    assert_eq!(fs::read(decrypted).unwrap(), plaintext);
}

#[test]
fn small_file_roundtrips() {
    roundtrip_bytes("small", b"Hello, Lvau.");
}

#[test]
fn empty_file_roundtrips() {
    roundtrip_bytes("empty", b"");
}

#[test]
fn unicode_text_roundtrips() {
    roundtrip_bytes("unicode", "Lvau encrypts UTF-8 text: こんにちは".as_bytes());
}

#[test]
fn binary_file_roundtrips() {
    let bytes: Vec<u8> = (0..=255).cycle().take(8192).collect();
    roundtrip_bytes("binary", &bytes);
}

#[test]
fn larger_file_roundtrips() {
    let bytes: Vec<u8> = (0..(CHUNK_SIZE + 37))
        .map(|i| ((i * 31) % 251) as u8)
        .collect();
    roundtrip_bytes("large", &bytes);
}

#[test]
fn wrong_password_fails() {
    let input = unique_path("wrong-password.input");
    let enc = unique_path("wrong-password.lvau");
    let dec = unique_path("wrong-password.output");

    fs::write(&input, b"Secret Data").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        SecretString::from("correct-password".to_string()),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let result = decrypt_file_password(
        &enc,
        &dec,
        SecretString::from("wrong-password".to_string()),
        None,
        None,
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn modified_ciphertext_fails() {
    let input = unique_path("tamper-ciphertext.input");
    let enc = unique_path("tamper-ciphertext.lvau");
    let dec = unique_path("tamper-ciphertext.output");
    let password = SecretString::from("password123".to_string());

    fs::write(&input, b"Data to be tampered").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let mut data = fs::read(&enc).unwrap();
    *data.last_mut().unwrap() ^= 0xFF;
    fs::write(&enc, data).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn modified_header_aad_fails() {
    let input = unique_path("tamper-header.input");
    let enc = unique_path("tamper-header.lvau");
    let dec = unique_path("tamper-header.output");
    let password = SecretString::from("password123".to_string());

    fs::write(&input, b"header-bound data").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    // Read the streaming format: 4 bytes length, then envelope, then payload.
    let data = fs::read(&enc).unwrap();
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
    envelope.header.profile = SecurityProfile::Archive;

    let new_env_bytes = postcard::to_allocvec(&envelope).unwrap();
    let new_len = new_env_bytes.len() as u32;

    let mut new_data = Vec::new();
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[4 + env_len..]);

    fs::write(&enc, new_data).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(matches!(result, Err(CryptoError::Validation(_))));
}

#[test]
fn truncated_file_fails() {
    let input = unique_path("truncated.input");
    let enc = unique_path("truncated.lvau");
    let dec = unique_path("truncated.output");
    let password = SecretString::from("password123".to_string());
    let bytes: Vec<u8> = (0..(CHUNK_SIZE * 2 + 11))
        .map(|i| (i % 251) as u8)
        .collect();

    fs::write(&input, bytes).unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let file = std::fs::OpenOptions::new().write(true).open(&enc).unwrap();
    let len = file.metadata().unwrap().len();
    file.set_len(len - 10).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn empty_password_cannot_create_a_capsule() {
    let input = unique_path("empty-password.input");
    let enc = unique_path("empty-password.lvau");
    fs::write(&input, b"not protected by an empty password").unwrap();

    let result = encrypt_file_password(
        &input,
        &enc,
        SecretString::from(String::new()),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    );

    assert!(matches!(result, Err(CryptoError::Validation(_))));
    assert!(!enc.exists());
}

#[test]
fn empty_password_is_rejected_before_kdf_work_on_decrypt_and_verify() {
    let input = unique_path("empty-password-decrypt.input");
    let enc = unique_path("empty-password-decrypt.lvau");
    let dec = unique_path("empty-password-decrypt.output");
    fs::write(&input, b"protected").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        SecretString::from("correct-password".to_string()),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let empty = SecretString::from(String::new());
    assert!(matches!(
        decrypt_file_password(&enc, &dec, empty.clone(), None, None),
        Err(CryptoError::Validation(_))
    ));
    assert!(matches!(
        verify_file_password(&enc, empty, None, None),
        Err(CryptoError::Validation(_))
    ));
    assert!(!dec.exists());
}

#[test]
fn failed_decryption_removes_partial_plaintext_tempfile() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    let enc = dir.path().join("encrypted.lvau");
    let output = dir.path().join("output.bin");
    let password = SecretString::from("password123".to_string());

    fs::write(&input, b"data that will fail authentication").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let mut data = fs::read(&enc).unwrap();
    *data.last_mut().unwrap() ^= 0x80;
    fs::write(&enc, data).unwrap();

    assert!(decrypt_file_password(&enc, &output, password, None, None).is_err());
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".output.bin.") && name.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "leftover plaintext files: {leftovers:?}"
    );
}

#[test]
fn declared_length_cannot_authenticate_a_valid_ciphertext_prefix() {
    let input = unique_path("declared-length-prefix.input");
    let enc = unique_path("declared-length-prefix.lvau");
    let dec = unique_path("declared-length-prefix.output");
    let password = SecretString::from("password123".to_string());
    let bytes: Vec<u8> = (0..(CHUNK_SIZE * 2 + 17))
        .map(|i| (i % 251) as u8)
        .collect();

    fs::write(&input, bytes).unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let data = fs::read(&enc).unwrap();
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
    envelope.plaintext_len = CHUNK_SIZE as u64;

    let new_envelope = postcard::to_allocvec(&envelope).unwrap();
    let first_ciphertext_chunk_len = CHUNK_SIZE + 16;
    let ciphertext_start = 4 + env_len;
    let mut forged = Vec::new();
    forged.extend_from_slice(&(new_envelope.len() as u32).to_le_bytes());
    forged.extend_from_slice(&new_envelope);
    forged
        .extend_from_slice(&data[ciphertext_start..ciphertext_start + first_ciphertext_chunk_len]);
    fs::write(&enc, forged).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(result.is_err(), "a valid ciphertext prefix was accepted");
}

#[test]
fn empty_payload_still_authenticates_immutable_envelope_fields() {
    let input = unique_path("empty-envelope.input");
    let enc = unique_path("empty-envelope.lvau");
    let dec = unique_path("empty-envelope.output");
    let password = SecretString::from("password123".to_string());

    fs::write(&input, []).unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let data = fs::read(&enc).unwrap();
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
    envelope.content_type = Some(lvau_protocol::envelope::ContentType::Bundle);

    let new_envelope = postcard::to_allocvec(&envelope).unwrap();
    let mut forged = Vec::new();
    forged.extend_from_slice(&(new_envelope.len() as u32).to_le_bytes());
    forged.extend_from_slice(&new_envelope);
    forged.extend_from_slice(&data[4 + env_len..]);
    fs::write(&enc, forged).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(
        result.is_err(),
        "empty payload metadata mutation was accepted"
    );
}

#[test]
fn trailing_ciphertext_is_rejected() {
    let input = unique_path("trailing-ciphertext.input");
    let enc = unique_path("trailing-ciphertext.lvau");
    let dec = unique_path("trailing-ciphertext.output");
    let password = SecretString::from("password123".to_string());

    fs::write(&input, b"authenticated payload").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let mut data = fs::read(&enc).unwrap();
    data.extend_from_slice(b"unauthenticated suffix");
    fs::write(&enc, data).unwrap();

    let result = decrypt_file_password(&enc, &dec, password, None, None);
    assert!(result.is_err(), "trailing ciphertext was ignored");
}

#[test]
fn random_garbage_input_fails_gracefully() {
    let enc = unique_path("garbage.lvau");
    let dec = unique_path("garbage.output");
    fs::write(&enc, b"not an lvau envelope").unwrap();

    let result = decrypt_file_password(
        &enc,
        &dec,
        SecretString::from("password123".to_string()),
        None,
        None,
    );

    // It fails with an IO error first because it tries to read length which exceeds file bounds
    assert!(result.is_err());
}

#[test]
fn inspect_works_without_password() {
    let input = unique_path("inspect.input");
    let enc = unique_path("inspect.lvau");

    fs::write(&input, b"inspectable").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        SecretString::from("password123".to_string()),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let header = inspect_envelope(&enc).unwrap();
    assert_eq!(header.magic, MAGIC_REAL);
    assert_eq!(header.version, CURRENT_VERSION);
    assert_eq!(header.profile, SecurityProfile::Fast);
    assert_eq!(header.recipients.len(), 1);
}

#[derive(serde::Serialize)]
struct V021EnvelopeFixture {
    header: EnvelopeHeader,
    plaintext_len: u64,
    nonce: [u8; 24],
    secondary_nonce: Option<[u8; 12]>,
    aad_hash: [u8; 32],
    metadata: Vec<u8>,
}

#[test]
fn v021_six_field_envelope_is_decoded_explicitly() {
    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: LEGACY_VERSION,
        profile: SecurityProfile::Fast,
        algorithm: AlgorithmId::XChaCha20Poly1305,
        kdf: Some(KdfParams::Argon2id {
            m_cost: 16_384,
            t_cost: 1,
            p_cost: 1,
            salt: [7; 16],
        }),
        recipients: vec![Recipient::Password {
            nonce: [3; 24],
            encrypted_file_key: vec![5; 48],
        }],
    };
    let header_bytes = postcard::to_allocvec(&header).unwrap();
    let fixture = V021EnvelopeFixture {
        header,
        plaintext_len: 42,
        nonce: [11; 24],
        secondary_nonce: None,
        aad_hash: Sha256::digest(header_bytes).into(),
        metadata: vec![1, 2, 3],
    };

    let bytes = postcard::to_allocvec(&fixture).unwrap();
    let decoded = decode_envelope_bytes(&bytes).unwrap();

    assert_eq!(decoded.header.version, LEGACY_VERSION);
    assert_eq!(decoded.plaintext_len, 42);
    assert_eq!(decoded.content_type, None);
    assert!(decoded.approvals.is_empty());
}

#[test]
fn v030_release_binary_fixture_decrypts() {
    let encoded: String = include_str!("../../tests/fixtures/v0_3_password.lvau.b64")
        .split_whitespace()
        .collect();
    let fixture = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let encrypted = unique_path("v0.3.0-fixture.lvau");
    let decrypted = unique_path("v0.3.0-fixture.output");
    fs::write(&encrypted, fixture).unwrap();

    decrypt_file_password(
        &encrypted,
        &decrypted,
        SecretString::from("synthetic-v0.3-fixture-password".to_string()),
        None,
        None,
    )
    .unwrap();

    assert_eq!(
        fs::read(&decrypted).unwrap(),
        "Lvau v0.3.0 compatibility fixture\nUTF-8: 日本語\n".as_bytes()
    );
}

#[test]
fn envelope_decoder_rejects_noncanonical_trailing_bytes() {
    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: LEGACY_VERSION,
        profile: SecurityProfile::Fast,
        algorithm: AlgorithmId::XChaCha20Poly1305,
        kdf: None,
        recipients: Vec::new(),
    };
    let header_bytes = postcard::to_allocvec(&header).unwrap();
    let fixture = V021EnvelopeFixture {
        header,
        plaintext_len: 0,
        nonce: [0; 24],
        secondary_nonce: None,
        aad_hash: Sha256::digest(header_bytes).into(),
        metadata: Vec::new(),
    };
    let mut bytes = postcard::to_allocvec(&fixture).unwrap();
    bytes.push(0);

    assert!(decode_envelope_bytes(&bytes).is_err());
}

#[test]
fn envelope_decoder_rejects_attacker_selected_argon2_costs() {
    let header = EnvelopeHeader {
        magic: MAGIC_REAL,
        version: LEGACY_VERSION,
        profile: SecurityProfile::Fast,
        algorithm: AlgorithmId::XChaCha20Poly1305,
        kdf: Some(KdfParams::Argon2id {
            m_cost: u32::MAX,
            t_cost: u32::MAX,
            p_cost: 1,
            salt: [7; 16],
        }),
        recipients: vec![Recipient::Password {
            nonce: [3; 24],
            encrypted_file_key: vec![5; 48],
        }],
    };
    let header_bytes = postcard::to_allocvec(&header).unwrap();
    let fixture = V021EnvelopeFixture {
        header,
        plaintext_len: 42,
        nonce: [11; 24],
        secondary_nonce: None,
        aad_hash: Sha256::digest(header_bytes).into(),
        metadata: Vec::new(),
    };

    let bytes = postcard::to_allocvec(&fixture).unwrap();
    assert!(matches!(
        decode_envelope_bytes(&bytes),
        Err(CryptoError::Validation(_))
    ));
}

#[test]
fn paranoid_profile_with_seed_roundtrips_and_rejects_wrong_seed() {
    let input = unique_path("paranoid.input");
    let enc = unique_path("paranoid.lvau");
    let dec = unique_path("paranoid.output");
    let dec_wrong = unique_path("paranoid-wrong.output");

    fs::write(&input, b"Top secret cascaded data").unwrap();

    let password = SecretString::from("top_secret_password".to_string());
    let seed = SecretString::from("my_random_seed_123".to_string());

    encrypt_file_password(
        &input,
        &enc,
        password.clone(),
        Some(seed.clone()),
        SecurityProfile::Paranoid,
        None,
        None,
        false,
    )
    .unwrap();

    decrypt_file_password(&enc, &dec, password.clone(), Some(seed), None).unwrap();
    assert_eq!(fs::read(&dec).unwrap(), b"Top secret cascaded data");

    let result = decrypt_file_password(
        &enc,
        &dec_wrong,
        password,
        Some(SecretString::from("wrong_seed".to_string())),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn hybrid_keypair_roundtrips() {
    let input = unique_path("keypair.input");
    let enc = unique_path("keypair.lvau");
    let dec = unique_path("keypair.output");
    let (private_key, public_key) = generate_keypair();

    fs::write(&input, b"hybrid recipient data").unwrap();
    encrypt_file_keypairs(
        &input,
        &enc,
        &[public_key],
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();
    decrypt_file_keypair(&enc, &dec, &private_key, None).unwrap();

    assert_eq!(fs::read(&dec).unwrap(), b"hybrid recipient data");
}

#[test]
fn empty_keypair_recipient_set_is_rejected() {
    let input = unique_path("empty-recipient.input");
    let enc = unique_path("empty-recipient.lvau");
    fs::write(&input, b"must remain recoverable").unwrap();

    let result = encrypt_file_keypairs(&input, &enc, &[], SecurityProfile::Fast, None, None, false);

    assert!(matches!(result, Err(CryptoError::Validation(_))));
    assert!(!enc.exists());
}

#[test]
fn every_keypair_recipient_can_verify_and_decrypt_in_memory() {
    let input = unique_path("second-recipient.input");
    let enc = unique_path("second-recipient.lvau");
    let (_private_one, public_one) = generate_keypair();
    let (private_two, public_two) = generate_keypair();
    let plaintext = b"the second recipient is equally authorized";
    fs::write(&input, plaintext).unwrap();

    encrypt_file_keypairs(
        &input,
        &enc,
        &[public_one, public_two],
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    verify_file_keypair(&enc, &private_two, None).unwrap();
    let encoded = fs::read(&enc).unwrap();
    assert_eq!(
        decrypt_memory_keypair(&encoded, &private_two).unwrap(),
        plaintext
    );
}

#[test]
fn corrupt_magic_bytes_fails() {
    let input = unique_path("magic.input");
    let enc = unique_path("magic.lvau");
    let dec = unique_path("magic.output");

    fs::write(&input, b"magic data").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        SecretString::from("password".to_string()),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    // Corrupt magic bytes
    let data = fs::read(&enc).unwrap();
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() >= 4 + env_len {
        let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
        envelope.header.magic = *b"EVIL";
        let new_env = postcard::to_allocvec(&envelope).unwrap();
        let new_len = new_env.len() as u32;

        let mut new_data = Vec::new();
        new_data.extend_from_slice(&new_len.to_le_bytes());
        new_data.extend_from_slice(&new_env);
        new_data.extend_from_slice(&data[4 + env_len..]);
        fs::write(&enc, new_data).unwrap();
    }

    let result = decrypt_file_password(
        &enc,
        &dec,
        SecretString::from("password".to_string()),
        None,
        None,
    );
    assert!(matches!(result, Err(CryptoError::Validation(_))));
}

#[test]
fn corrupt_version_fails() {
    let input = unique_path("version.input");
    let enc = unique_path("version.lvau");
    let dec = unique_path("version.output");

    fs::write(&input, b"version data").unwrap();
    encrypt_file_password(
        &input,
        &enc,
        SecretString::from("password".to_string()),
        None,
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    // Corrupt version
    let data = fs::read(&enc).unwrap();
    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() >= 4 + env_len {
        let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
        envelope.header.version = 999;
        let new_env = postcard::to_allocvec(&envelope).unwrap();
        let new_len = new_env.len() as u32;

        let mut new_data = Vec::new();
        new_data.extend_from_slice(&new_len.to_le_bytes());
        new_data.extend_from_slice(&new_env);
        new_data.extend_from_slice(&data[4 + env_len..]);
        fs::write(&enc, new_data).unwrap();
    }

    let result = decrypt_file_password(
        &enc,
        &dec,
        SecretString::from("password".to_string()),
        None,
        None,
    );
    assert!(matches!(result, Err(CryptoError::Validation(_))));
}

#[test]
fn wrong_keypair_fails() {
    let input = unique_path("wrong_keypair.input");
    let enc = unique_path("wrong_keypair.lvau");
    let dec = unique_path("wrong_keypair.output");

    let (_, public_key1) = generate_keypair();
    let (private_key2, _) = generate_keypair();

    fs::write(&input, b"hybrid recipient data").unwrap();
    encrypt_file_keypairs(
        &input,
        &enc,
        &[public_key1],
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap();

    let result = decrypt_file_keypair(&enc, &dec, &private_key2, None);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn zero_x25519_peer_is_rejected_by_hybrid_contributory_helper() {
    let secret = x25519_dalek::StaticSecret::from([42u8; 32]);
    let public = x25519_dalek::PublicKey::from([0u8; 32]);

    assert!(matches!(
        derive_contributory_x25519(&secret, &public),
        Err(CryptoError::Validation(
            "Recipient X25519 public key is non-contributory"
        ))
    ));
}

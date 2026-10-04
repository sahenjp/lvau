#![no_main]

use libfuzzer_sys::fuzz_target;
use lvau_core::crypto::keys::generate_keypair;
use lvau_core::crypto::suite::v3::{file, mutable_file, rekey_file};
use lvau_core::crypto::suite::V3SuiteId;
use lvau_protocol::envelope::SecurityProfile;
use secrecy::SecretString;
use std::fs;
use tempfile::tempdir;

fn run(data: &[u8]) {
    let Ok(directory) = tempdir() else {
        return;
    };
    let input = directory.path().join("input");
    let legacy = directory.path().join("legacy.lvau");
    let a4 = directory.path().join("a4.lvau");
    let tampered = directory.path().join("tampered.lvau");
    let added = directory.path().join("added.lvau");
    let both_suites = directory.path().join("both-suites.lvau");
    let removed_mlkem = directory.path().join("removed-mlkem.lvau");
    let removed_x25519 = directory.path().join("removed-x25519.lvau");
    let removed = directory.path().join("removed.lvau");
    let changed = directory.path().join("changed.lvau");
    let hybrid_added = directory.path().join("hybrid-added.lvau");
    let hybrid_two = directory.path().join("hybrid-two.lvau");
    let hybrid_removed = directory.path().join("hybrid-removed.lvau");
    let layered = directory.path().join("layered.lvau");
    let layered_hybrid = directory.path().join("layered-hybrid.lvau");
    let payload = &data[..data.len().min(4096)];
    if fs::write(&input, payload).is_err() {
        return;
    }

    let password = SecretString::from("fuzz-only-password".to_owned());
    if file::encrypt_file_password(
        &input,
        &legacy,
        password.clone(),
        SecurityProfile::Fast,
        false,
        None,
    )
    .is_err()
    {
        return;
    }

    let (private, public) = generate_keypair();
    let (second_private, second_public) = generate_keypair();
    if rekey_file::add_mlkem_recipient(&legacy, &a4, password.clone(), &public, false).is_err() {
        return;
    }

    let Ok(mut bytes) = fs::read(&a4) else {
        return;
    };
    let original = bytes.clone();
    for chunk in data.chunks(3) {
        if bytes.is_empty() {
            break;
        }
        let low = chunk[0] as usize;
        let high = chunk.get(1).copied().unwrap_or(0) as usize;
        let index = (low | (high << 8)) % bytes.len();
        bytes[index] ^= chunk.get(2).copied().unwrap_or(0) | 1;
    }
    if !data.is_empty() && bytes == original {
        bytes[0] ^= 1;
    }
    if fs::write(&tampered, bytes).is_err() {
        return;
    }

    let password_check = mutable_file::verify_file_password(&tampered, password.clone(), None);
    let key_check = mutable_file::verify_file_keypair(&tampered, &private, None);
    if data.is_empty() {
        assert!(password_check.is_ok());
        assert!(key_check.is_ok());
    } else {
        assert!(password_check.is_err());
        assert!(key_check.is_err());
    }

    let add = rekey_file::add_mlkem_recipient(&a4, &added, password.clone(), &second_public, false);
    assert!(add.is_ok());
    assert!(mutable_file::verify_file_keypair(&added, &private, None).is_ok());
    assert!(mutable_file::verify_file_keypair(&added, &second_private, None).is_ok());

    assert!(
        rekey_file::add_x25519_recipient(&a4, &both_suites, password.clone(), &public, false)
            .is_ok()
    );
    assert!(rekey_file::remove_mlkem_recipient_with_keypair(
        &both_suites,
        &removed_mlkem,
        &private,
        &public,
        false,
    )
    .is_ok());
    assert!(mutable_file::verify_file_keypair(&removed_mlkem, &private, None).is_ok());
    assert!(rekey_file::remove_x25519_recipient_with_keypair(
        &both_suites,
        &removed_x25519,
        &private,
        &public,
        false,
    )
    .is_ok());
    assert!(mutable_file::verify_file_keypair(&removed_x25519, &private, None).is_ok());

    assert!(
        rekey_file::add_hybrid_recipient(&a4, &hybrid_added, password.clone(), &public, false)
            .is_ok()
    );
    assert!(mutable_file::verify_file_keypair(&hybrid_added, &private, None).is_ok());
    assert!(
        rekey_file::add_hybrid_recipient(
            &hybrid_added,
            &hybrid_two,
            password.clone(),
            &second_public,
            false
        )
        .is_ok()
    );
    assert!(
        rekey_file::remove_hybrid_recipient_with_keypair(
            &hybrid_two,
            &hybrid_removed,
            &second_private,
            &public,
            false
        )
        .is_ok()
    );
    assert!(mutable_file::verify_file_keypair(&hybrid_removed, &second_private, None).is_ok());

    if file::encrypt_file_password_with_suite(
        &input,
        &layered,
        password.clone(),
        SecurityProfile::Fast,
        V3SuiteId::Aes256GcmSivXChaCha20Poly1305,
        false,
        None,
    )
    .is_err()
    {
        return;
    }
    assert!(
        rekey_file::add_hybrid_recipient(&layered, &layered_hybrid, password.clone(), &public, false)
            .is_ok()
    );
    assert!(mutable_file::verify_file_keypair(&layered_hybrid, &private, None).is_ok());
    assert!(mutable_file::verify_file_password(&layered_hybrid, password.clone(), None).is_ok());

    let remove =
        rekey_file::remove_mlkem_recipient(&tampered, &removed, password.clone(), &public, false);
    if data.is_empty() {
        assert!(remove.is_ok());
        assert!(mutable_file::verify_file_password(&removed, password.clone(), None).is_ok());
    } else {
        assert!(remove.is_err());
        assert!(!removed.exists());
    }

    let change = rekey_file::change_password(
        &tampered,
        &changed,
        password,
        SecretString::from("fuzz-only-new-password".to_owned()),
        None,
        false,
    );
    if data.is_empty() {
        assert!(change.is_ok());
        assert!(mutable_file::verify_file_password(
            &changed,
            SecretString::from("fuzz-only-new-password".to_owned()),
            None,
        )
        .is_ok());
    } else {
        assert!(change.is_err());
        assert!(!changed.exists());
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4096 {
        run(data);
    }
});

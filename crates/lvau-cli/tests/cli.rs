use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn lvau() -> Command {
    Command::cargo_bin("lvau-cli").unwrap()
}

fn write_secret_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn payload_frames(path: &Path) -> Vec<u8> {
    let bytes = fs::read(path).unwrap();
    let envelope_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    bytes[4 + envelope_len..].to_vec()
}

fn mutable_password_material(path: &Path) -> ([u8; 16], [u8; 24], u8) {
    let bytes = fs::read(path).unwrap();
    let envelope_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let envelope: lvau_protocol::envelope_v3::V3MutableEnvelope =
        postcard::from_bytes(&bytes[4..4 + envelope_len]).unwrap();
    envelope
        .slots
        .iter()
        .find_map(|slot| match slot {
            lvau_protocol::envelope_v3::V3MutableSlot::Password(slot) => {
                Some((slot.salt, slot.wrapping_nonce, slot.profile_id))
            }
            _ => None,
        })
        .unwrap()
}

#[test]
fn help_lists_core_commands() {
    lvau()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("decrypt"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("bundle"))
        .stdout(predicate::str::contains("sign-keygen"))
        .stdout(predicate::str::contains("sign"))
        .stdout(predicate::str::contains("verify-signature"));
}

#[test]
fn version_flag_works() {
    lvau()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("lvau-cli"));
}

#[test]
fn password_roundtrip_and_inspect_work() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");

    fs::write(&input, "hello from lvau").unwrap();
    write_secret_file(&password, "correct horse battery staple\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    lvau()
        .args(["inspect", "--in-file", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Lvau envelope metadata"))
        .stdout(predicate::str::contains("Argon2id"));

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());
}

#[test]
fn experimental_v3_password_roundtrip_inspect_and_verify_work() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("v3-input.txt");
    let encrypted = dir.path().join("v3-input.lvau");
    let decrypted = dir.path().join("v3-output.txt");
    let password = dir.path().join("password.txt");
    let wrong_password = dir.path().join("wrong-password.txt");

    fs::write(&input, "experimental v3 payload").unwrap();
    write_secret_file(&password, "correct horse battery staple\n");
    write_secret_file(&wrong_password, "wrong\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
        ])
        .assert()
        .success();

    lvau()
        .args(["inspect", "--in-file", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Version:   3 (experimental)"))
        .stdout(predicate::str::contains("LV3-XC20P"));

    lvau()
        .args([
            "verify",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            wrong_password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Decryption failed"));
    assert!(!decrypted.exists());

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());

    fs::write(&decrypted, "do not replace").unwrap();
    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Use --force"));
    assert_eq!(fs::read_to_string(&decrypted).unwrap(), "do not replace");

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());
}

#[test]
fn rekey_rotate_root_changes_password_without_mutating_the_source() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let rotated = dir.path().join("rotated.lvau");
    let output = dir.path().join("output.txt");
    let old_password = dir.path().join("old-password.txt");
    let new_password = dir.path().join("new-password.txt");

    fs::write(&input, b"rotate the v3 root key").unwrap();
    write_secret_file(&old_password, "old-passphrase\n");
    write_secret_file(&new_password, "new-passphrase\n");
    lvau()
        .args([
            "encrypt",
            "--password",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            old_password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();
    let original_capsule = fs::read(&encrypted).unwrap();

    lvau()
        .args([
            "rekey",
            "rotate-root",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            rotated.to_str().unwrap(),
            "--password-file",
            old_password.to_str().unwrap(),
            "--new-password-file",
            new_password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("previous credentials"));

    assert_eq!(fs::read(&encrypted).unwrap(), original_capsule);
    lvau()
        .args([
            "verify",
            "--password",
            "--in-file",
            rotated.to_str().unwrap(),
            "--password-file",
            new_password.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "verify",
            "--password",
            "--in-file",
            rotated.to_str().unwrap(),
            "--password-file",
            old_password.to_str().unwrap(),
        ])
        .assert()
        .failure();
    lvau()
        .args([
            "decrypt",
            "--password",
            "--in-file",
            rotated.to_str().unwrap(),
            "--out-file",
            output.to_str().unwrap(),
            "--password-file",
            new_password.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(output).unwrap(), fs::read(input).unwrap());
}

#[test]
fn rekey_rotate_root_rejects_wrong_password_and_preserves_existing_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let output = dir.path().join("rotated.lvau");
    let password = dir.path().join("password.txt");
    let wrong_password = dir.path().join("wrong-password.txt");
    let new_password = dir.path().join("new-password.txt");

    fs::write(&input, b"rotate root without losing the old file").unwrap();
    write_secret_file(&password, "old-passphrase\n");
    write_secret_file(&wrong_password, "wrong-passphrase\n");
    write_secret_file(&new_password, "new-passphrase\n");
    lvau()
        .args([
            "encrypt",
            "--password",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    lvau()
        .args([
            "rekey",
            "rotate-root",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            output.to_str().unwrap(),
            "--password-file",
            wrong_password.to_str().unwrap(),
            "--new-password-file",
            new_password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .failure();
    assert!(!output.exists());

    fs::write(&output, b"keep this existing output").unwrap();
    lvau()
        .args([
            "rekey",
            "rotate-root",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            output.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--new-password-file",
            new_password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .failure();
    assert_eq!(fs::read(&output).unwrap(), b"keep this existing output");

    lvau()
        .args([
            "rekey",
            "rotate-root",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            output.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--new-password-file",
            new_password.to_str().unwrap(),
            "--profile",
            "fast",
            "--force",
        ])
        .assert()
        .success();
}

#[test]
fn experimental_v3_hpke_recipient_roundtrip_and_wrong_key_rejection() {
    let dir = tempdir().unwrap();
    let key_dir = dir.path().join("keys");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input-hpke.lvau");
    let decrypted = dir.path().join("output.txt");
    let wrong_output = dir.path().join("wrong-output.txt");
    fs::create_dir(&key_dir).unwrap();
    fs::write(&input, b"experimental v3 HPKE recipient").unwrap();

    for name in ["recipient", "wrong"] {
        lvau()
            .args(["keygen", "--out-base", key_dir.join(name).to_str().unwrap()])
            .assert()
            .success();
    }

    lvau()
        .args([
            "encrypt",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--pub-key",
            key_dir.join("recipient.lvau-pub").to_str().unwrap(),
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    lvau()
        .args([
            "inspect",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("X25519-HPKE"))
        .stdout(predicate::str::contains("key_id"));
    lvau()
        .args([
            "verify",
            "--priv-key",
            key_dir.join("recipient.lvau-key").to_str().unwrap(),
            "--in-file",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            key_dir.join("recipient.lvau-key").to_str().unwrap(),
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());

    lvau()
        .args([
            "decrypt",
            "--priv-key",
            key_dir.join("wrong.lvau-key").to_str().unwrap(),
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            wrong_output.to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(!wrong_output.exists());
}

#[test]
fn rekey_convert_a3_to_a4_keeps_source_and_payload_frames() {
    let dir = tempdir().unwrap();
    let key_dir = dir.path().join("keys");
    let input = dir.path().join("input.bin");
    let a3 = dir.path().join("input-a3.lvau");
    let a4 = dir.path().join("input-a4.lvau");
    let output = dir.path().join("output.bin");
    fs::create_dir(&key_dir).unwrap();
    fs::write(&input, vec![0x37; 1024 * 1024 + 17]).unwrap();

    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("source").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "encrypt",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--recipient-suite",
            "x25519-hpke",
            "--pub-key",
            key_dir.join("source.lvau-pub").to_str().unwrap(),
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            a3.to_str().unwrap(),
        ])
        .assert()
        .success();
    let original_a3 = fs::read(&a3).unwrap();
    let encrypted_frames = payload_frames(&a3);

    lvau()
        .args([
            "rekey",
            "convert-a3",
            "--in-file",
            a3.to_str().unwrap(),
            "--out-file",
            a4.to_str().unwrap(),
            "--priv-key",
            key_dir.join("source.lvau-key").to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&a3).unwrap(), original_a3);
    assert_eq!(payload_frames(&a4), encrypted_frames);
    lvau()
        .args(["inspect", "--in-file", a4.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("envelope revision A4"));
    lvau()
        .args([
            "verify",
            "--priv-key",
            key_dir.join("source.lvau-key").to_str().unwrap(),
            "--in-file",
            a4.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            key_dir.join("source.lvau-key").to_str().unwrap(),
            "--in-file",
            a4.to_str().unwrap(),
            "--out-file",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(output).unwrap(), fs::read(input).unwrap());
}

#[test]
fn mutable_v3_mlkem_roundtrip_inspect_verify_and_wrong_key_rejection() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input-a4.lvau");
    let decrypted = dir.path().join("output.txt");
    let wrong_output = dir.path().join("wrong-output.txt");
    fs::write(&input, vec![0x5a; 1024 * 1024 + 17]).unwrap();

    for name in ["recipient", "wrong"] {
        lvau()
            .args([
                "keygen",
                "--out-base",
                dir.path().join(name).to_str().unwrap(),
            ])
            .assert()
            .success();
    }

    lvau()
        .args([
            "encrypt",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--recipient-suite",
            "ml-kem-768",
            "--pub-key",
            dir.path().join("recipient.lvau-pub").to_str().unwrap(),
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args(["inspect", "--in-file", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("envelope revision A4"))
        .stdout(predicate::str::contains("ML-KEM-768 key ID"));
    lvau()
        .args([
            "verify",
            "--priv-key",
            dir.path().join("recipient.lvau-key").to_str().unwrap(),
            "--in-file",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("recipient.lvau-key").to_str().unwrap(),
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());

    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("wrong.lvau-key").to_str().unwrap(),
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            wrong_output.to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(!wrong_output.exists());
}

#[test]
fn rekey_mlkem_with_private_key_preserves_payload_and_credentials() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("encrypted.lvau");
    let added = dir.path().join("added.lvau");
    let removed = dir.path().join("removed.lvau");
    let password_added = dir.path().join("password-added.lvau");
    let password = dir.path().join("password.txt");
    fs::write(&input, b"keypair rekeying must not rewrite payload frames").unwrap();
    write_secret_file(&password, "new-passphrase\n");

    for name in ["a", "b"] {
        lvau()
            .args([
                "keygen",
                "--out-base",
                dir.path().join(name).to_str().unwrap(),
            ])
            .assert()
            .success();
    }

    lvau()
        .args([
            "encrypt",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--recipient-suite",
            "ml-kem-768",
            "--pub-key",
            dir.path().join("a.lvau-pub").to_str().unwrap(),
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    let encrypted_bytes = fs::read(&encrypted).unwrap();
    let frames = payload_frames(&encrypted);

    let refused = dir.path().join("refused.lvau");
    lvau()
        .args([
            "rekey",
            "remove-recipient",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            refused.to_str().unwrap(),
            "--priv-key",
            dir.path().join("a.lvau-key").to_str().unwrap(),
            "--pub-key",
            dir.path().join("a.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(!refused.exists());
    assert_eq!(fs::read(&encrypted).unwrap(), encrypted_bytes);

    lvau()
        .args([
            "rekey",
            "add-recipient",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            added.to_str().unwrap(),
            "--priv-key",
            dir.path().join("a.lvau-key").to_str().unwrap(),
            "--pub-key",
            dir.path().join("b.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&encrypted).unwrap(), encrypted_bytes);
    assert_eq!(payload_frames(&added), frames);

    lvau()
        .args([
            "verify",
            "--priv-key",
            dir.path().join("b.lvau-key").to_str().unwrap(),
            "--in-file",
            added.to_str().unwrap(),
        ])
        .assert()
        .success();
    let b_output = dir.path().join("b-output.txt");
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("b.lvau-key").to_str().unwrap(),
            "--in-file",
            added.to_str().unwrap(),
            "--out-file",
            b_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&b_output).unwrap(), fs::read(&input).unwrap());
    let added_bytes = fs::read(&added).unwrap();

    lvau()
        .args([
            "rekey",
            "remove-recipient",
            "--in-file",
            added.to_str().unwrap(),
            "--out-file",
            removed.to_str().unwrap(),
            "--priv-key",
            dir.path().join("a.lvau-key").to_str().unwrap(),
            "--pub-key",
            dir.path().join("b.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&added).unwrap(), added_bytes);
    assert_eq!(payload_frames(&removed), frames);

    let removed_b_output = dir.path().join("removed-b-output.txt");
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("b.lvau-key").to_str().unwrap(),
            "--in-file",
            removed.to_str().unwrap(),
            "--out-file",
            removed_b_output.to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(!removed_b_output.exists());
    let a_output = dir.path().join("a-output.txt");
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("a.lvau-key").to_str().unwrap(),
            "--in-file",
            removed.to_str().unwrap(),
            "--out-file",
            a_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&a_output).unwrap(), fs::read(&input).unwrap());
    let removed_bytes = fs::read(&removed).unwrap();

    lvau()
        .args([
            "rekey",
            "change-password",
            "--in-file",
            removed.to_str().unwrap(),
            "--out-file",
            password_added.to_str().unwrap(),
            "--priv-key",
            dir.path().join("a.lvau-key").to_str().unwrap(),
            "--new-password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&removed).unwrap(), removed_bytes);
    assert_eq!(payload_frames(&password_added), frames);
    lvau()
        .args([
            "verify",
            "--password-file",
            password.to_str().unwrap(),
            "--in-file",
            password_added.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "verify",
            "--priv-key",
            dir.path().join("a.lvau-key").to_str().unwrap(),
            "--in-file",
            password_added.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn rekey_add_and_remove_mlkem_preserve_payload_and_password_access() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let legacy = dir.path().join("legacy.lvau");
    let added = dir.path().join("added.lvau");
    let removed = dir.path().join("removed.lvau");
    let password_output = dir.path().join("password-output.txt");
    let key_output = dir.path().join("key-output.txt");
    let removed_key_output = dir.path().join("removed-key-output.txt");
    let password = dir.path().join("password.txt");
    fs::write(&input, b"payload frames must remain unchanged").unwrap();
    write_secret_file(&password, "old-passphrase\n");
    lvau()
        .args([
            "keygen",
            "--out-base",
            dir.path().join("recipient").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "encrypt",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            legacy.to_str().unwrap(),
        ])
        .assert()
        .success();
    let legacy_bytes = fs::read(&legacy).unwrap();

    lvau()
        .args([
            "rekey",
            "add-recipient",
            "--in-file",
            legacy.to_str().unwrap(),
            "--out-file",
            added.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--pub-key",
            dir.path().join("recipient.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&legacy).unwrap(), legacy_bytes);
    assert_eq!(payload_frames(&added), payload_frames(&legacy));
    lvau()
        .args(["inspect", "--in-file", added.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Fast"))
        .stdout(predicate::str::contains("Argon2id"));

    lvau()
        .args([
            "decrypt",
            "--password-file",
            password.to_str().unwrap(),
            "--in-file",
            added.to_str().unwrap(),
            "--out-file",
            password_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("recipient.lvau-key").to_str().unwrap(),
            "--in-file",
            added.to_str().unwrap(),
            "--out-file",
            key_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&password_output).unwrap(),
        fs::read(&input).unwrap()
    );
    assert_eq!(fs::read(&key_output).unwrap(), fs::read(&input).unwrap());
    let added_bytes = fs::read(&added).unwrap();

    lvau()
        .args([
            "rekey",
            "remove-recipient",
            "--in-file",
            added.to_str().unwrap(),
            "--out-file",
            removed.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--pub-key",
            dir.path().join("recipient.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&added).unwrap(), added_bytes);
    assert_eq!(payload_frames(&removed), payload_frames(&legacy));
    lvau()
        .args([
            "verify",
            "--password-file",
            password.to_str().unwrap(),
            "--in-file",
            removed.to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "decrypt",
            "--priv-key",
            dir.path().join("recipient.lvau-key").to_str().unwrap(),
            "--in-file",
            removed.to_str().unwrap(),
            "--out-file",
            removed_key_output.to_str().unwrap(),
        ])
        .assert()
        .failure();
    assert!(!removed_key_output.exists());
}

#[test]
fn rekey_change_password_refreshes_material_and_rejects_old_credentials() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let legacy = dir.path().join("legacy.lvau");
    let changed = dir.path().join("changed.lvau");
    let changed_again = dir.path().join("changed-again.lvau");
    let old_password = dir.path().join("old-password.txt");
    let new_password = dir.path().join("new-password.txt");
    let newest_password = dir.path().join("newest-password.txt");
    fs::write(&input, b"password wrapping changes, payload does not").unwrap();
    write_secret_file(&old_password, "old-passphrase\n");
    write_secret_file(&new_password, "new-passphrase\n");
    write_secret_file(&newest_password, "newest-passphrase\n");
    lvau()
        .args([
            "encrypt",
            "--format",
            "v3",
            "--suite",
            "lv3-xc20p",
            "--password-file",
            old_password.to_str().unwrap(),
            "--profile",
            "fast",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            legacy.to_str().unwrap(),
        ])
        .assert()
        .success();

    lvau()
        .args([
            "rekey",
            "change-password",
            "--in-file",
            legacy.to_str().unwrap(),
            "--out-file",
            changed.to_str().unwrap(),
            "--password-file",
            old_password.to_str().unwrap(),
            "--new-password-file",
            new_password.to_str().unwrap(),
            "--profile",
            "balanced",
        ])
        .assert()
        .success();
    let first = mutable_password_material(&changed);
    assert_eq!(first.2, 1);
    assert_eq!(payload_frames(&changed), payload_frames(&legacy));
    lvau()
        .args([
            "verify",
            "--password-file",
            old_password.to_str().unwrap(),
            "--in-file",
            changed.to_str().unwrap(),
        ])
        .assert()
        .failure();

    lvau()
        .args([
            "rekey",
            "change-password",
            "--in-file",
            changed.to_str().unwrap(),
            "--out-file",
            changed_again.to_str().unwrap(),
            "--password-file",
            new_password.to_str().unwrap(),
            "--new-password-file",
            newest_password.to_str().unwrap(),
        ])
        .assert()
        .success();
    let second = mutable_password_material(&changed_again);
    assert_eq!(second.2, first.2);
    assert_ne!(second.0, first.0);
    assert_ne!(second.1, first.1);
    assert_eq!(payload_frames(&changed_again), payload_frames(&legacy));
    lvau()
        .args([
            "verify",
            "--password-file",
            new_password.to_str().unwrap(),
            "--in-file",
            changed_again.to_str().unwrap(),
        ])
        .assert()
        .failure();
    lvau()
        .args([
            "verify",
            "--password-file",
            newest_password.to_str().unwrap(),
            "--in-file",
            changed_again.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn experimental_v3_layered_suite_roundtrip_inspect_and_verify_work() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("v3-layered-input.txt");
    let encrypted = dir.path().join("v3-layered-input.lvau");
    let decrypted = dir.path().join("v3-layered-output.txt");
    let password = dir.path().join("password.txt");

    fs::write(&input, "experimental v3 layered payload").unwrap();
    write_secret_file(&password, "correct horse battery staple\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
            "--format",
            "v3",
            "--suite",
            "lv3-aesgcmsiv-xc20p",
        ])
        .assert()
        .success();

    lvau()
        .args(["inspect", "--in-file", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Version:   3 (experimental)"))
        .stdout(predicate::str::contains("LV3-AESGCMSIV-XC20P"));

    lvau()
        .args([
            "inspect",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("LV3-AESGCMSIV-XC20P"));

    lvau()
        .args([
            "verify",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());
}

#[test]
fn experimental_v3_requires_supported_suite_and_single_file_mode() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let password = dir.path().join("password.txt");
    fs::write(&input, "payload").unwrap();
    write_secret_file(&password, "test\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--format",
            "v3",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires --suite lv3-xc20p"));

    lvau()
        .args([
            "keygen",
            "--out-base",
            dir.path().join("recipient").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--pub-key",
            dir.path().join("recipient.lvau-pub").to_str().unwrap(),
            "--format",
            "v3",
            "--suite",
            "lv3-aesgcmsiv-xc20p",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("password encryption only"));

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--format",
            "v3",
            "--suite",
            "bogus-suite",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires --suite lv3-xc20p"));

    lvau()
        .args([
            "bundle",
            "pack",
            "--in-dir",
            dir.path().to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--format",
            "v3",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument '--format'"));
}

#[test]
fn inspect_json_output_is_valid() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let password = dir.path().join("password.txt");

    fs::write(&input, "json test").unwrap();
    write_secret_file(&password, "testpass\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    let output = lvau()
        .args([
            "inspect",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json_str = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["command"], "inspect");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["data"]["magic"], "LVAU");
    assert_eq!(parsed["data"]["signed"], false);
}

#[test]
fn wrong_password_fails_without_output() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");
    let wrong_password = dir.path().join("wrong-password.txt");

    fs::write(&input, "secret").unwrap();
    write_secret_file(&password, "correct\n");
    write_secret_file(&wrong_password, "wrong\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            wrong_password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Decryption failed"));

    assert!(!decrypted.exists());
}

#[test]
fn corrupted_file_fails_gracefully() {
    let dir = tempdir().unwrap();
    let encrypted = dir.path().join("garbage.lvau");
    let decrypted = dir.path().join("output.txt");
    let password = dir.path().join("password.txt");

    fs::write(&encrypted, "not an envelope").unwrap();
    write_secret_file(&password, "correct\n");

    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            decrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn refuses_overwrite_without_force() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let password = dir.path().join("password.txt");

    fs::write(&input, "secret").unwrap();
    fs::write(&encrypted, "existing").unwrap();
    write_secret_file(&password, "correct\n");

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    assert_eq!(fs::read_to_string(&encrypted).unwrap(), "existing");
}

#[test]
fn recipient_groups_lifecycle() {
    let dir = tempdir().unwrap();
    let group = dir.path().join("mygroup.toml");
    let key_dir = dir.path().join("keys");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");

    fs::create_dir_all(&key_dir).unwrap();
    fs::write(&input, "secret message for group").unwrap();

    // 1. Generate two keypairs
    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("alice").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("bob").to_str().unwrap(),
        ])
        .assert()
        .success();

    // 2. Create group
    lvau()
        .args(["recipients", "group", "create", group.to_str().unwrap()])
        .assert()
        .success();

    // 3. Add to group
    lvau()
        .args([
            "recipients",
            "group",
            "add",
            group.to_str().unwrap(),
            "--pub-key",
            key_dir.join("alice.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();
    lvau()
        .args([
            "recipients",
            "group",
            "add",
            group.to_str().unwrap(),
            "--pub-key",
            key_dir.join("bob.lvau-pub").to_str().unwrap(),
        ])
        .assert()
        .success();

    // 4. List group
    lvau()
        .args(["recipients", "group", "list", group.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("bob"));

    // 5. Encrypt with group
    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--recipient-group",
            group.to_str().unwrap(),
        ])
        .assert()
        .success();

    // 6. Decrypt with Alice
    let dec_alice = dir.path().join("dec_alice.txt");
    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            dec_alice.to_str().unwrap(),
            "--priv-key",
            key_dir.join("alice.lvau-key").to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(&dec_alice).unwrap(),
        "secret message for group"
    );

    // 7. Decrypt with Bob
    let dec_bob = dir.path().join("dec_bob.txt");
    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            dec_bob.to_str().unwrap(),
            "--priv-key",
            key_dir.join("bob.lvau-key").to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(&dec_bob).unwrap(),
        "secret message for group"
    );
}

#[test]
fn bundle_policy_diff_lifecycle() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src_dir");
    let bundle = dir.path().join("mybundle.lvau");
    let extracted = dir.path().join("extracted_dir");
    let policy = dir.path().join("policy.toml");
    let key_dir = dir.path().join("keys");
    let password = dir.path().join("password.txt");

    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&key_dir).unwrap();
    fs::write(src.join("file1.txt"), "hello world").unwrap();
    fs::write(src.join("file2.txt"), "secret data").unwrap();
    write_secret_file(&password, "super_secure_password\n");

    // Generate keys
    lvau()
        .args([
            "keygen",
            "--out-base",
            key_dir.join("alice").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Create a policy
    lvau()
        .args(["policy", "create", "--out-file", policy.to_str().unwrap()])
        .assert()
        .success();

    // Pack the bundle
    lvau()
        .args([
            "bundle",
            "pack",
            "--in-dir",
            src.to_str().unwrap(),
            "--out-file",
            bundle.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Lint the bundle against the policy
    lvau()
        .args([
            "policy",
            "lint",
            "--in-file",
            bundle.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Result: PASS"));

    // Preflight inspect the bundle
    lvau()
        .args(["preflight", "--in-file", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Present: false"))
        .stdout(predicate::str::contains("Preflight Report for:"));

    // Verify the bundle
    lvau()
        .args([
            "bundle",
            "verify",
            "--in-file",
            bundle.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle verified: 2 files"));

    let bundle2 = dir.path().join("mybundle2.lvau");
    fs::write(src.join("file1.txt"), "hello world changed").unwrap();
    lvau()
        .args([
            "bundle",
            "pack",
            "--in-dir",
            src.to_str().unwrap(),
            "--out-file",
            bundle2.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Diff the bundle
    lvau()
        .args([
            "bundle",
            "diff",
            "--old-file",
            bundle.to_str().unwrap(),
            "--new-file",
            bundle2.to_str().unwrap(),
            "--old-password-file",
            password.to_str().unwrap(),
            "--new-password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("file1.txt"));

    // Extract the bundle
    lvau()
        .args([
            "bundle",
            "extract",
            "--in-file",
            bundle.to_str().unwrap(),
            "--out-dir",
            extracted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(extracted.join("file1.txt")).unwrap(),
        "hello world"
    );
}

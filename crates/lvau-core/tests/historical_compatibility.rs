use base64::{engine::general_purpose::STANDARD, Engine};
use lvau_core::crypto::{decrypt_file_password, inspect_envelope, read_envelope_from_path};
use lvau_protocol::envelope::{AlgorithmId, KdfParams, Recipient, SecurityProfile};
use secrecy::SecretString;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Fixture {
    fixture: String,
    source_tag: String,
    source_commit: String,
    format: String,
    format_version: u16,
    algorithm: String,
    profile: String,
    password: String,
    password_description: String,
    plaintext: String,
    plaintext_description: String,
    plaintext_sha256: String,
    fixture_sha256: String,
    writer_command: String,
    provenance: Provenance,
}

#[derive(Deserialize)]
struct Provenance {
    kind: String,
    asset_url: String,
    original_artifact_sha256: String,
    binary_sha256: String,
    version_output: Option<String>,
    version_discrepancy: Option<String>,
    source_package_version: String,
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn current_reader_decrypts_tagged_historical_password_fixtures() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/historical_compatibility.json")).unwrap();
    assert_eq!(fixtures.len(), 4);

    for fixture in fixtures {
        assert!(matches!(
            fixture.source_tag.as_str(),
            "v0.2.0" | "v0.2.1" | "v0.4.0" | "v0.5.0"
        ));
        assert_eq!(fixture.source_commit.len(), 40);
        assert_eq!(
            fixture.format,
            format!("Lvau envelope v{}", fixture.format_version)
        );
        assert_eq!(fixture.algorithm, "XChaCha20Poly1305");
        assert_eq!(fixture.profile, "Fast");
        assert!(fixture
            .password_description
            .starts_with("Synthetic test-only"));
        assert!(fixture
            .plaintext_description
            .starts_with("Synthetic two-line"));
        assert_eq!(fixture.provenance.kind, "official-release-binary");
        assert!(fixture.provenance.asset_url.contains(&fixture.source_tag));
        assert_eq!(fixture.provenance.original_artifact_sha256.len(), 64);
        assert_eq!(fixture.provenance.binary_sha256.len(), 64);
        assert!(!fixture.provenance.source_package_version.is_empty());
        if matches!(fixture.source_tag.as_str(), "v0.2.0" | "v0.2.1") {
            assert!(fixture.provenance.version_output.is_none());
        } else {
            assert!(fixture.provenance.version_output.is_some());
        }
        if fixture.source_tag == "v0.2.0" {
            assert!(fixture
                .provenance
                .version_discrepancy
                .as_deref()
                .is_some_and(|value| value.contains("exits 2")));
        }
        assert!(fixture.writer_command.starts_with("lvau-cli encrypt "));

        let encoded = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(&fixture.fixture),
        )
        .unwrap();
        let encrypted = STANDARD
            .decode(encoded.split_whitespace().collect::<String>())
            .unwrap();
        assert_eq!(sha256(&encrypted), fixture.fixture_sha256);
        assert_eq!(
            sha256(fixture.plaintext.as_bytes()),
            fixture.plaintext_sha256
        );

        let dir = tempfile::tempdir().unwrap();
        let encrypted_path = dir.path().join("fixture.lvau");
        let plaintext_path = dir.path().join("plaintext.txt");
        std::fs::write(&encrypted_path, encrypted).unwrap();

        let envelope = read_envelope_from_path(&encrypted_path).unwrap();
        assert_eq!(envelope.header.version, fixture.format_version);
        assert_eq!(envelope.plaintext_len, fixture.plaintext.len() as u64);
        let header = inspect_envelope(&encrypted_path).unwrap();
        assert_eq!(header.version, fixture.format_version);
        assert_eq!(header.profile, SecurityProfile::Fast);
        assert_eq!(header.algorithm, AlgorithmId::XChaCha20Poly1305);
        assert!(matches!(
            header.kdf,
            Some(KdfParams::Argon2id {
                m_cost: 16_384,
                t_cost: 1,
                p_cost: 1,
                ..
            })
        ));
        assert_eq!(header.recipients.len(), 1);
        assert!(matches!(&header.recipients[0], Recipient::Password { .. }));

        decrypt_file_password(
            &encrypted_path,
            &plaintext_path,
            SecretString::from(fixture.password),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(plaintext_path).unwrap(),
            fixture.plaintext.as_bytes()
        );
    }
}

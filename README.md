<h1 align="center">
  <img src="./assets/lvau-wordmark.svg" alt="Lvau" width="340">
</h1>

<p align="center"><strong>Encrypt local files.</strong></p>

<p align="center">English · <a href="README_ja.md">日本語</a></p>

<p align="center">
  <a href="https://github.com/lasder-ca/lvau/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

Lvau is an experimental Rust workspace for local file encryption. It includes a CLI, reusable cryptographic library, versioned `.lvau` format, native GUI, and self-extracting archive prototype. The current release is **0.5.0**.

> [!NOTE]
> **AI usage disclosure:** AI tools were used for roughly half of the development of Lvau.

> [!WARNING]
> Lvau has not completed an independent security audit, and formats may change before 1.0. Read [SECURITY.md](SECURITY.md) and [the threat model](docs/THREAT_MODEL.md) before using it for important data.

## Quick start

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli verify --password --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

Password input is hidden. For local automation, use a password file with restricted permissions:

```sh
printf '%s' 'replace-with-a-strong-passphrase' > password.txt
chmod 600 password.txt
lvau-cli encrypt \
  --in-file secret.txt \
  --out-file secret.txt.lvau \
  --password-file password.txt
```

On Windows, restrict the password file ACL to the account running Lvau. The automatic broad-permission check is Unix-only. Never commit passwords, private keys, seeds, recovery shares, or credential files.

## What Lvau provides

| Capability | Status |
|---|---|
| Password encryption with XChaCha20-Poly1305, Argon2id, and HKDF-SHA256 | Available for testing |
| Streaming encryption and authenticated verification | Available for testing |
| Public format inspection without payload decryption | Available for testing |
| Password-protected directory bundles with encrypted manifests | Available for testing |
| Ed25519 author signatures | Available for testing |
| JSON output for inspect, verify, preflight, report, and policy lint | Schema version 1 |
| Hybrid recipient encryption and cascade profiles | Experimental |
| Approval metadata, recovery workflows, GUI, and self-extracting archives | Experimental |

Policy linting is experimental and advisory. It is not automatically enforced by `decrypt` or `bundle extract`; run `policy lint` or `preflight` as a separate workflow step when a local policy must pass before decryption or extraction.

## Automation and Nelo

Automation-facing JSON uses a versioned top-level envelope where implemented. See [the JSON output contract](docs/JSON_OUTPUT.md) for the exact command coverage and compatibility rules.

[Nelo](https://github.com/lasder-ca/Nelo) can own an `lvau-cli` process for the lifetime of an HTTP request. Its example terminates encryption on request cancellation, bounds uploads, and removes request-owned temporary plaintext. See [the Nelo integration guide](docs/integrations/NELO.md).

## Brand assets

- [`assets/lvau-wordmark.svg`](./assets/lvau-wordmark.svg) — primary lowercase wordmark for README and wider brand surfaces.
- [`assets/lvau-icon.svg`](./assets/lvau-icon.svg) — rounded product/app icon using the Lvau monogram.
- [`assets/lvau-symbol.svg`](./assets/lvau-symbol.svg) — transparent monochrome monogram for compact placements.
- [`assets/favicon.svg`](./assets/favicon.svg) — high-contrast browser and small-size icon.

The identity is deliberately neutral and monochrome: warm off-white with near-black, with light/dark-aware SVG variants where appropriate. The marks are vector paths and do not depend on external fonts.

## Build from source

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --locked --workspace --release
```

Binaries are written to `target/release/`. Run `lvau-cli <command> --help` for authoritative command options.

## Security boundaries

Lvau can protect payload confidentiality and integrity only while passwords, private keys, and the local machine remain secure. It does not protect against malware, keyloggers, a compromised operating system, weak passwords, stolen keys, malicious output consumers, or loss of every credential.

The envelope exposes algorithm identifiers, KDF parameters, recipient slots, nonces, approximate plaintext size, and optional public labels. Bundle paths and file metadata are encrypted by default. Signatures, approvals, releases, and recovery fields are separate annotations and must be verified and interpreted explicitly.

See [the format documentation](docs/FORMAT.md) for the v2/v1 layout and migration guidance.

## Workspace

| Crate | Responsibility |
|---|---|
| `lvau-protocol` | Serialized envelope and manifest types |
| `lvau-core` | Cryptography, parsing, files, bundles, signatures, policy, and recovery |
| `lvau-cli` | Command-line interface and automation output |
| `lvau-gui` | Experimental native interface over `lvau-core` |
| `lvau-stub` | Experimental self-extracting archive support |

## Development

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

Read [CONTRIBUTING.md](CONTRIBUTING.md), [the roadmap](docs/ROADMAP.md), and [the changelog](CHANGELOG.md). Report sensitive vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## License

Lvau is available under the [MIT License](LICENSE).

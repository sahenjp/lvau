# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-10-04

### Security

- Reject encrypted output when the streamed input length differs from the length committed in its envelope.
- Refuse existing core output paths by default, add explicit overwrite APIs, and use atomic replacement without deleting the previous file first across core, GUI, CLI, and SFX outputs.
- Stage and validate all bundle entries before per-file atomic publication. A failure during the final multi-file commit can still leave an already-published prefix.
- Update `event-listener` to 5.4.2 to address RUSTSEC-2026-0221.
- Replace yanked transitive `der` 0.8.0 with 0.8.1 in the locked ML-KEM dependency tree.
- HPKE recipient wrapping uses RFC 9180 Base mode with X25519, HKDF-SHA256, and ChaCha20-Poly1305. It does not prove recipient possession to the sender or authenticate senders. Lvau's canonical X25519 wire restriction is stricter than RFC serialization.
- Revision A4 authenticates a mutable password/X25519/ML-KEM-768/hybrid root-wrap table independently from the payload binding. ML-KEM-768 uses the KEM with a Lvau-specific XChaCha20-Poly1305 key-wrap composition; the RustCrypto implementation is not independently audited. The experimental dual-wrap hybrid slot is not a KEM combiner: breaking either component exposes the file root key.
- `rekey rotate-root` creates a new encrypted artifact and cannot revoke old copies or credentials already obtained. Legacy A3 recipient tables remain immutable; A4 slot updates preserve the root and likewise cannot revoke earlier copies.

### Added

- Add experimental single-file format-v3 paths for `LV3-XC20P`: password, X25519 HPKE revision A3, and ML-KEM-768 revision A4. Format v2 remains the default writer.
- Add experimental layered v3 payload suite `LV3-AESGCMSIV-XC20P` for password files (`--format v3 --suite lv3-aesgcmsiv-xc20p`): AES-256-GCM-SIV inner encryption followed by XChaCha20-Poly1305 outer encryption, with independently derived keys, independent nonce domains, fixed order, and per-layer AAD binding suite, layer, envelope commitment, chunk index, lengths, and final-frame state. A3 recipient paths remain `LV3-XC20P`-only; `rekey rotate-root` preserves the layered suite through full re-encryption.
- Extend the layered v3 payload suite to A4 recipient envelopes: ML-KEM-768 creation accepts the layered suite, A4 validation/binding/frame codecs resolve the envelope suite (suite-1 files verify byte-for-byte as before), A4 password-slot wrap info is suite-qualified, and frame-preserving `rekey` slot updates carry single or layered suites into A4. Revision A3 stays single-layer.
- Add experimental dual-wrap hybrid A4 recipient slots (`--recipient-suite hybrid-x25519-mlkem`): the file root key is wrapped independently for the X25519-HPKE and ML-KEM-768 components under one tag-3 slot with an algorithm-qualified hybrid key ID, openable with either private component. This is not a KEM combiner and stays experimental pending review. Direct creation, add/remove rekey operations, both payload suites, and CLI inspect/JSON display are covered.
- Add the v0.3.0 official release fixture to the historical compatibility matrix (now v0.2.0/v0.2.1/v0.3.0/v0.4.0/v0.5.0), extend the A4 update fuzz target with hybrid add/remove and layered-suite sources, index the normative v3 test vectors in `docs/FORMAT_V3_DRAFT.md`, and document support/deprecation/emergency-disable rules in `docs/SUPPORT_POLICY.md`.
- Add `rekey add-recipient`, `remove-recipient`, and `change-password` to rewrap A4 slots while preserving payload frame bytes.
- Add `rekey convert-a3`, requiring public-key coverage for all original A3 recipients and preserving the original encrypted payload frames.
- Add `rekey rotate-root` for decrypting and re-encrypting legacy password-v3 files with a new root key.
- Use a random temporary directory for CLI SFX payloads instead of a predictable sibling filename.

### Migration

- No re-encryption is required: format v1 and v2 remain readable and v2 remains the default writer. All v3 paths stay explicit opt-in.
- Automation JSON contracts are unchanged (`schema_version == 1` still selects the contract).
- Experimental v3 files written by pre-release `wip/lvau-v1` builds are not covered by any stability promise; rewrite them with the released writer if needed.

## [0.5.0] - 2026-07-19

### Security

- Bundle pack, list, verify, and extract now process file contents with a fixed 64 KiB buffer instead of allocating the complete plaintext payload. The serialized manifest is independently capped at 16 MiB.
- Bundle extraction authenticates every manifest entry before creating any named output and writes each file through a same-directory temporary file before atomic persistence.
- Bundle packing hashes every source in a first pass and verifies size and BLAKE3 again while streaming the second pass, rejecting files that change during packing.
- Existing format-v2 cipher suites now share explicit, fixed HKDF labels, nonce derivation, and chunk-AAD helpers with known-answer tests. This refactor preserves the v2 byte construction and does not introduce format v3.

### Added

- Added an internal versioned cryptographic-suite registry that distinguishes payload encryption layers from recipient algorithms, signatures, padding, and legacy LCO obfuscation.
- Added fixed key-schedule and nonce/AAD vectors as foundations for the separately reviewed experimental format-v3 work planned for 0.6.0.
- Added JSON output schema version 1. Machine-readable commands return a top-level `schema_version`, `command`, `status`, and `data` envelope.

### Changed

- Updated all workspace crates to version 0.5.0.
- Migrated secret-string handling to `secrecy` 0.10 and X25519 handling to `x25519-dalek` 3 with the operating-system random generator feature.
- Bundle payload layout and envelope format remain compatible with existing v2 readers; v1 and v2 reads are retained.
- CLI JSON output for inspect, verify, preflight, report, and policy lint now uses the versioned envelope contract.

### Migration

- No re-encryption is required for existing v2 files. Format v1 and v2 remain readable.
- Automation consuming JSON must read command-specific fields from `data` and may use `schema_version == 1` to select the contract.
- LCO remains legacy experimental obfuscation and is not counted or described as an encryption layer.

## [0.4.0] - 2026-07-17

### Security

- New output uses envelope format v2, which AEAD-authenticates the declared plaintext length, nonces, recipient/KDF header, content type, public label, private metadata bytes, and policy-override marker. This closes keyless prefix-truncation and metadata-downgrade paths in format v1.
- Empty plaintext now emits an authenticated frame, and decryptors reject trailing ciphertext.
- Added bounded, exact envelope decoding plus recipient-count/type, wrapped-key length, nonce, and fixed Argon2id-profile validation before expensive allocation or KDF work.
- Author signatures now bind their stored fingerprint/comment, while v2 approval signatures bind the envelope, ciphertext, fingerprint, and comment. Trusting a signer remains an explicit caller decision.
- Bundle validation now checks canonical manifests, path safety, case-insensitive collisions, integer overflow, bounds, overlapping ranges, and every entry's BLAKE3 digest.
- Bundle packing rejects special files, and extraction refuses existing symlink/reparse-point or multi-hardlink targets even with `--force`.
- Recovery share v2 replaces the offline-guessable `SHA-256(secret)` identifier with a random set ID and replaces vulnerable `sharks` with the corrected `blahaj` implementation.
- Updated `crossbeam-epoch` to 0.9.20 for RUSTSEC-2026-0204, removed unused Postcard/Heapless default dependencies, and made `cargo-audit` 0.22.2 run from a validated, expiry-documented configuration.
- Private key, signing key, recovery share, and encrypted/decrypted output writes use restricted same-directory temporary files and fsync; Unix private outputs are mode `0600`.
- Unix password/seed files are rejected when group or other permission bits are present.

### Changed

- All workspace crates are versioned `0.4.0`; existing format-v1 and legacy v0.2 envelopes remain readable, while old binaries are not expected to read new format-v2 output.
- CLI prompts and diagnostics use stderr; JSON policy/preflight failures return a non-zero exit status and verify JSON is serialized safely.
- Common envelope parsing is shared by decrypt, inspect, policy, preflight, and bundle inspection paths.
- Legacy read compatibility is covered by a capsule fixture generated with the v0.3.0 release binary.
- Multi-recipient keypair decrypt/verify tries every compatible recipient slot rather than only the first.
- Bundle verification decrypts once instead of repeating the KDF and payload decryption.
- GUI cryptographic work now runs off the render thread, reports processed bytes, clears password/seed fields after dispatch, bounds its log buffer, and builds experimental SFX outputs by streaming into an atomic temporary file.
- CI uses locked dependencies, commit-pinned Actions, three-OS tests, tag/workspace/CHANGELOG validation, checksums, CycloneDX SBOMs, and GitHub artifact attestations.

### Fixed

- Empty `inspect` input and empty LCO nonces no longer panic.
- Failed encryption/decryption no longer leaves named temporary plaintext/output files behind.
- Signing-key fingerprints can no longer be spoofed by editing unsigned metadata.
- API-side fixed test-token authentication, pass-the-hash API-key lookup, cross-tenant recipient-group overwrite, empty-password encryption, blocking-job permit lifetime, Firebase fail-open configuration, and event-loop bcrypt work were fixed in the adjacent `lvau-api` repository.
- The adjacent website now enforces its Vercel-compatible 4 MB Lvau limit, rejects empty Lvau passwords, and accurately states that files and passwords transit the server-side proxy/API.

### Migration

- No CLI command or legacy read path is intentionally removed. To obtain v2 protections, decrypt an older capsule with a trusted Lvau version and re-encrypt it with 0.4.0; preserve and verify signatures separately because re-encryption creates a new artifact.
- Recovery share files remain decodable; newly generated share sets use version 2 identifiers.

## [0.3.0] - 2026-07-04

### Added
- **Capsule Policy**: Enforce strict linting rules on `.lvau` capsules before creation or at inspection time via `CapsulePolicy` TOML specification.
- **Preflight Verification**: Safely audit `.lvau` capsules without decryption keys, generating detailed human-readable or JSON reports via `lvau-cli preflight`.
- **Approval Seals**: Support appending Ed25519 co-signatures to the envelope's public metadata without decrypting the payload, via `lvau-cli approve`.
- **Encrypted Manifest Diffing**: Decrypt and compare the `BundleManifest` of two directory bundles to generate `Added/Removed/Modified/Unchanged` reports via `lvau-cli bundle diff`.
- **Verification Reporting**: Full static and dynamic verification reports via `lvau-cli report`.
- **Recipient Groups**: Encrypt files for a local group config of multiple hybrid public keys via `lvau-cli recipients group`.
- **Sealed Bundle Mode**: Full implementation of `bundle pack`, `extract`, `inspect`, `list`, and `verify` with dry-run capabilities and path traversal protections.
- **Signed Envelopes**: Optional Ed25519 signatures covering public envelope and ciphertext via `sign-keygen`, `sign`, and `verify-signature`.
- **Recovery Shares**: Split master keys into Shamir Secret Sharing (SSS) shares via `recovery split`, `combine`, and `inspect`.
- **Recipient Slots**: Support for wrapping one file-encryption key for multiple recipients at initial encryption time.
- **Structured Secret Mode**: Developer workflows for dotfiles via `secret encrypt`, `edit`, `decrypt`, and `print`.
- **Hardened Testing**: Comprehensive test suite including corrupt-envelope, truncated-file, path traversal, and wrong-password checks.

### Changed
- Differentiated Lvau as a "sealed encryption toolkit" prioritizing inspectability, recoverable artifacts, and safe developer workflows.
- Strengthened atomic writes and secret zeroization.

## [0.2.0] - 2026-07-03

### Added

- **Sealed Bundle Mode**: `lvau-cli bundle pack` encrypts a directory into a single `.lvau` file, hiding file names, sizes, and structure in an encrypted manifest.
- **Bundle Manifest**: Cryptographically binds relative paths, file sizes, and BLAKE3 hashes to the payload.
- **Security Profile Check**: Verifies that the capsule's profile satisfies the minimum required security level (e.g., `Paranoid`).
- **Memory Hardness Warnings**: Warns if the KDF memory cost is suspiciously low or zero.
- **Public Label**: Optional plaintext label visible during inspection (e.g., for routing or CI tagging).

### Fixed

- Path traversal vulnerabilities during bundle extraction (`..` or absolute paths are rejected).
- Clippy warnings and Rust formatting inconsistencies.

## [0.1.0] - 2026-07-01

Initial public release preparation.

### Added

- **CLI** (`lvau-cli`): encrypt, decrypt, inspect, and keygen commands
- **GUI** (`lvau-gui`): cross-platform native GUI with password and keypair support
- **Encryption**: XChaCha20-Poly1305 AEAD as default algorithm
- **KDF**: Argon2id with configurable security profiles (fast, balanced, archive, paranoid)
- **Key separation**: HKDF-SHA256 for deriving independent encryption keys from master key
- **Versioned envelope**: `.lvau` format with magic bytes, version field, and AAD-bound metadata
- **Metadata inspection**: read envelope metadata without decrypting content
- **Truncation detection**: envelope stores plaintext length and rejects mismatched decrypt output
- **CLI overwrite safety**: output files are not replaced unless `--force` is supplied
- **CLI automation**: `--password-file` and `--seed-file` support non-interactive local workflows
- **Parallel encryption**: 1 MB chunked processing via Rayon
- **Hybrid keypair**: X25519 + ML-KEM-768 key exchange (experimental)
- **Cascade encryption**: AES-256-GCM + XChaCha20-Poly1305 cascade in paranoid profile
- **Self-extracting archives**: SFX `.exe` output via `lvau-stub`
- **Zeroized secrets**: key material cleared from memory after use
- **CI**: GitHub Actions for fmt, clippy, test, build
- **Release workflow**: cross-platform binary builds (Linux, Windows, macOS)
- **Security audit**: weekly `cargo audit` via GitHub Actions
- **Documentation**: threat model, format specification, security policy, contributing guide

### Security

- This release has **not been formally audited**
- The `.lvau` format is **not yet stable** and may change before v1.0
- Hybrid keypair encryption, cascade profiles, GUI, and SFX remain experimental

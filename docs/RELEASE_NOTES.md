# Lvau 0.6.0

Lvau 0.6.0 introduces experimental format v3 as an explicit opt-in writer. Format v2 remains the default writer, and format v1/v2 files remain readable (historical fixtures v0.2.0/v0.2.1/v0.3.0/v0.4.0/v0.5.0 are checked in tests).

## Highlights

- Single-file format-v3 paths for `LV3-XC20P`: password, X25519 HPKE revision A3, and ML-KEM-768 revision A4.
- Layered payload suite `LV3-AESGCMSIV-XC20P` (AES-256-GCM-SIV inner, XChaCha20-Poly1305 outer) for password files and A4 recipients; A3 stays single-layer.
- Experimental dual-wrap hybrid A4 recipient slots (X25519+ML-KEM, either component opens; not a KEM combiner).
- A4 `rekey` operations: add/remove recipient (including hybrid), change password, `convert-a3`, and `rotate-root`.
- Normative v3 test-vector index, support/deprecation/emergency-disable policy, and extended A4 fuzz coverage.

## Compatibility

No re-encryption is required for existing files. JSON automation contracts are unchanged (`schema_version == 1`).

## Security status

Lvau remains unaudited and pre-1.0. The v3 revisions, the layered suite, and the hybrid construction are experimental and have not completed independent review. This release should not be described as formally audited, unbreakable, military-grade, or suitable for protecting critical data without independent evaluation.

---

# Lvau 0.5.0

Lvau 0.5.0 is a scalability and cryptographic-foundation release. It does not introduce a new encrypted-file format: new output remains envelope v2, and supported v1/v2 input remains readable.

## Highlights

- Bounded-memory directory bundles with a fixed 64 KiB content buffer.
- Two-pass source validation during packing and authenticate-before-write extraction.
- Atomic per-file bundle extraction with no partial named plaintext outputs on failure.
- Versioned payload-suite registry and compatibility-fixed HKDF, nonce, and AAD helpers.
- `secrecy` 0.10 and `x25519-dalek` 3 dependency migrations.
- JSON output schema version 1 for automation-facing commands.

## Compatibility

The bundle payload layout and envelope-v2 cryptographic construction are unchanged. Existing format-v1 and format-v2 capsules remain readable. LCO remains legacy experimental obfuscation and is not treated as an encryption layer.

## Security status

Lvau remains unaudited and pre-1.0. This release should not be described as formally audited, unbreakable, military-grade, or suitable for protecting critical data without independent evaluation.

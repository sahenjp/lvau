# Development Status

Updated: 2026-10-04. Working branch `wip/lvau-v1` continues the local v1.0
development line; do not reset or discard uncommitted work without explicit
authorization.

## Current worktree

Previous and current changes are in:

- `CHANGELOG.md`, `Cargo.lock`, `README.md`, `README_ja.md`
- `crates/lvau-cli/src/main.rs`, `crates/lvau-cli/tests/cli.rs`
- `crates/lvau-core/src/bundle_stream.rs`
- `crates/lvau-core/src/crypto/mod.rs`, `crypto/output.rs`, `crypto/tests.rs`
- `crates/lvau-core/src/crypto/suite/v3.rs`, `crypto/suite/v3_file.rs`,
  `crypto/suite/v3_hpke_file.rs`, `crypto/suite/v3_mutable_file.rs`,
  `crypto/suite/v3_mlkem.rs`, `crypto/suite/v3_rekey_file.rs`,
  `crypto/suite/v3_convert_file.rs`
- `crates/lvau-core/Cargo.toml` (adds `aes-gcm-siv 0.12` for the layered suite)
- `crates/lvau-gui/src/main.rs`
- `crates/lvau-protocol/src/lib.rs`, `src/envelope_v3.rs`
- `docs/FORMAT.md`, `docs/FORMAT_V3_DRAFT.md`, `docs/ROADMAP.md`,
  `docs/THREAT_MODEL.md`, `docs/BENCHMARK_A3_A4.md`
- `fuzz/` protocol-envelope and A4 file-update targets
- `scripts/benchmark-formats.sh`, `scripts/benchmark-v3-operations.py`
- `AGENTS.md`, workspace dependency manifests, and CLI tests

No release version, v2 wire encoding, v1/v2 decoder, or default writer format
was changed. `Cargo.lock` pins experimental HPKE 0.14.1 and ML-KEM 0.3.2, adds
HMAC for the A4 header authenticator, updates `event-listener` to 5.4.2, and
replaces yanked `der` 0.8.0 with 0.8.1.

## Implemented and verified before this continuation

- Core file outputs refuse existing destinations by default. Explicit
  `*_with_overwrite` APIs are used by CLI/GUI force paths and share
  `crypto::output::persist_temp_path`.
- Bundle extraction authenticates and stages every entry, validates destinations
  before and after staging, then atomically publishes per file. A later commit
  failure can leave an already-published prefix; hostile concurrent destination
  mutation is outside the supported threat model.
- Experimental v3 `LV3-XC20P` retains legacy password-v3 and HPKE A3 readers and
  adds A4 with a root-key-authenticated mutable slot table, immutable payload
  binding, password slots, X25519 HPKE slots, and pure ML-KEM-768 slots. The A4
  slot table permits one password and up to 64 recipients; the envelope cap is
  96 KiB. V2 remains the default writer. V3 is not frozen or independently
  reviewed.
- A3 follows RFC 9180 Base mode X25519/HKDF-SHA256/ChaCha20-Poly1305, with
  algorithm-qualified key IDs, domain-separated file context, canonical X25519
  input restrictions stricter than RFC serialization, and an RFC open vector.
  Base mode does not authenticate the sender or prove recipient possession.
- A4 pure ML-KEM-768 uses FIPS 203 KEM plus a Lvau-specific HKDF/XChaCha root-key
  wrap (not HPKE). The existing hybrid key file supplies its ML-KEM component;
  X25519 is not used. The NIST ACVP encapsulation vector (group 2, case 26)
  passes. RustCrypto `ml-kem` 0.3.2 states it has not been independently audited.
- A4 supports adding/removing X25519 HPKE and ML-KEM recipients, and adding or
  changing the Argon2id password/profile. These operations authenticate the old
  credential, A4 header, and all frames, then copy encrypted frames unchanged
  and atomically publish a verified new envelope. Pure-recipient A4 files can
  authorize updates with a retained private key; removal of the last usable
  credential is rejected. `rekey rotate-root` remains full re-encryption for
  legacy password-v3 and does not revoke old copies.
- V2/v3 encryption sizes are read from the opened input handle and compared with
  the bytes actually streamed. SFX payloads use a random temporary directory.
- Linux release benchmark script: `scripts/benchmark-formats.sh` (1, 256, and
  1024 MiB; 3 runs; Fast profile; encrypt/decrypt/compare; time, CPU, max RSS,
  and output size).

Latest Linux checks (2026-10-04, layered-suite change): `cargo fmt --all --check`,
Clippy with `-D warnings`, full workspace tests, release workspace build, CLI
self-test (5/5), layered CLI encrypt/inspect/verify/decrypt roundtrip plus a
wrong-password negative case, and `git diff --check` all pass.
`cargo tree --duplicates` shows the expected separate legacy and HPKE/ML-KEM
crypto stacks (now also AES-GCM-SIV 0.12 alongside AES-GCM 0.10) plus existing
GUI transitive duplicates. `cargo audit` reports no
vulnerabilities and three allowlisted unmaintained-crate warnings
(`number_prefix`, `paste`, `ttf-parser`).
The separate fuzz lockfile audit also reports no vulnerabilities; it has one
allowlisted `atomic-polyfill` unmaintained warning through Postcard/Heapless.

Fuzzing actually ran: `envelope_v3` for 60 seconds (178,251 executions, no
crash), covering bounded postcard parsing plus the production revision and
inspect readers; `a4_updates` for 30 seconds (118 executions, no crash), covering
payload tampering, password rewrap, and cross-suite keypair-authorized removal.
KDF/KEM/file work limits the second target's throughput. A first parser-target
run exposed an incorrect canonicality assertion in the harness, not a product
fault; the harness was corrected, the crash input replayed successfully, and a
noncanonical-varint rejection regression test was added.

Cross-target checks: full workspace Windows GNU `cargo check` passed. Core
all-target `cargo check` passed for Windows/MSVC and macOS/aarch64 with BLAKE3's
pure-Rust feature because this Linux host lacks the MSVC C compiler and Apple
Clang/SDK. Full default-feature MSVC/macOS workspace builds and native Windows/
macOS test execution remain unverified. CI defines native Windows/macOS tests,
but was not run because doing so would require a push/PR.
The prior Linux 1 GiB password-v3 benchmark median was about 20 MiB max RSS
versus 92–94 MiB for v2. The new 256 MiB A3/A4 run measured about 7.3–7.5 MiB
RSS for direct recipient decrypt/verify, 21–22 MiB for slot updates, 0.82–0.85 s
for A4 updates, and 0.88 s for legacy root rotation. See
`docs/BENCHMARK_A3_A4.md`; these single-host measurements do not establish a
general performance ranking.

## Decisions and invariants

- Preserve v1/v2 reads and v2 default writes. Do not reuse v2 identifiers or
  change v2 authentication semantics.
- V3 supports password-v3 in `LV3-XC20P` and the layered
  `LV3-AESGCMSIV-XC20P` (password files and A4 recipient envelopes, explicit
  opt-in), plus immutable HPKE A3 (`LV3-XC20P` only) and mutable
  ML-KEM/HPKE/password A4 single-file envelopes; it does not support bundles,
  ML-DSA signatures, layered suites in A3, or a frozen compatibility contract.
- A3/A4 have unique `(format_version=3, envelope_revision)` identities. The
  password envelope remains the exact legacy implicit revision. Unknown
  revisions fail closed without decoder fallback.
- Root-key rotation means decrypting and encrypting a new file; it cannot revoke
  old copies or secrets already obtained.
- Bundle publication is atomic per file, not a whole-directory transaction.
  Publication uses path-based temporary-file rename. A process able to mutate
  the destination directory can replace a staging pathname between verification
  and rename; concurrent destination-directory mutation is unsupported and
  remains a pre-1.0 security limitation.
- Never commit, push, tag, publish, deploy, or discard existing work without
  explicit authorization.

## Remaining work

- Issue #11 (0.6.0 layered AEAD): the password-v3 layered suite
  `LV3-AESGCMSIV-XC20P` is implemented with chunk KAT, tamper/malformed vectors,
  file-level roundtrip and suite-relabelling tests, and CLI coverage. A4 accepts
  both payload suites with suite-conditional binding and slot-wrap info
  (suite-1 files verify unchanged); frame-preserving `rekey` carries the source
  suite into A4. A3 stays single-layer. The layered construction still needs
  independent review before any promotion.
- Issue #12: A3 X25519 HPKE plus the RFC 9180 vector and A4 pure ML-KEM-768 plus
  NIST ACVP vector are implemented. ML-DSA and X25519+ML-KEM hybrid A4 slots are
  absent. Independent review is still required; the ML-KEM implementation is
  unaudited.
- Issue #13: A4 add/remove X25519/ML-KEM recipients and password/profile updates
  preserve payload frames; root rotation is separate full re-encryption. Old
  copies remain usable. A3 recipient tables remain immutable.
- `rekey convert-a3` migrates A3 only when the destination public-key set covers
  every original recipient. It preserves the exact A3 frame commitment and
  ciphertext bytes; the source remains unchanged.
- Issue #13's literal requirement to authenticate the recipient table before
  trying any slot is incompatible with its root-key-derived HMAC: the root must
  first be unwrapped. A4 selects one matching slot, verifies the table MAC, then
  processes frames; issue/design wording needs maintainer resolution before #13
  can be considered fully closed.
- An independent review reproduced a P2 issue: removing one algorithm slot was
  rejected even when the same hybrid private key retained a second usable slot.
  Removal now checks the updated table and has a cross-suite regression test.
  A second independent reviewer confirmed both cross-suite removal directions,
  source/ciphertext preservation, and last-credential rejection, with no further
  findings. AI review is not an external cryptographic audit.
- Expand the envelope and A4 update fuzz corpora/campaigns, add rekey-specific
  fuzz coverage and an ongoing CI job, and complete historical fixture coverage
  before format freeze. Resolve or re-review the time-bounded `quick-xml` RustSec
  exceptions in `.cargo/audit.toml` before 2026-10-15.
- Native Windows/MSVC and macOS validation are not available in the current
  environment; the previous MSVC cross-check failed because the MSVC compiler
  toolchain is absent. The Windows GNU target check is not a substitute.
- Run the full release checklist and keep v1.0.0 blocked until its review,
  compatibility, platform, and release-engineering gates pass.

## Agent/runtime note

The parent runtime identifies as `openai/gpt-6-luna`. The Task interface used
for children does not expose a selectable/verifiable child model ID or reasoning
effort, so child runs must not be reported as confirmed Luna runs. No Sol model
was used.

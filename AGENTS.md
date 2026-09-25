# Lvau Development Instructions

## Purpose and layout

Lvau is experimental, local-first encryption software for single files,
directory bundles, structured secrets, and inspectable workflow metadata.

- `lvau-protocol`: serialized envelope, recipient, signature, and manifest
  data types. Keep this crate small and serialization-conscious.
- `lvau-core`: cryptography, streaming payload I/O, bundles, signatures,
  policies, recovery, and reports. CLI/GUI must reuse it.
- `lvau-cli`: command parsing, prompts, automation output, and exit behavior.
- `lvau-gui`: desktop presentation and background task coordination; do not
  duplicate cryptographic operations here.
- `lvau-stub`: self-extracting artifact launcher support.
- `.github`: CI, dependency monitoring, security checks, and authorized
  tag-triggered releases.

The public site is maintained in the adjacent `lattes.jp` repository and the
OCI-hosted HTTP service in the adjacent `lvau-api` repository. The Rust
workspace does not contain an OCI SDK or OCI control-plane client.

## Supported development environment

Use WSL2 with Ubuntu 26.04 and Linux paths/commands for primary development.
Use native Windows/macOS CI for platform proof. Keep `Cargo.lock` authoritative
and pass `--locked` in validation commands.

## Required validation

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

Run `cargo audit` when installed. For CLI behavior, also run an actual
encrypt/inspect/verify/decrypt roundtrip and negative cases. Site changes need
its test, lint, typecheck, and production-build commands. API changes need
`cargo fmt --all --check`, Clippy with `-D warnings`, tests, release build, and
`shellcheck` for modified shell scripts.

## Security and compatibility rules

- Never invent cryptographic primitives or treat reversible transforms as
  encryption boundaries.
- Do not expose secrets through `Debug`, logs, errors, CLI arguments, JSON,
  fixtures, screenshots, or documentation. Use synthetic test-only values.
- Bound attacker-controlled lengths before allocation; reject truncation,
  overflow, trailing data, invalid resource combinations, and unknown formats.
- Do not finalize unverified plaintext at the requested destination. Use
  same-directory temporary files, flush/fsync where supported, atomic rename,
  and restrictive permissions for secret material.
- Preserve existing `.lvau` reads. Any write-format change requires a new
  version, a precise legacy decoder, tamper/resource tests, `docs/FORMAT.md`,
  `CHANGELOG.md`, and migration instructions. Never reuse a format version for
  changed authentication semantics. Before 1.0, an explicitly experimental
  envelope revision may distinguish a new wire version only when the
  `(format_version, envelope_revision)` tuple is unique, every older encoding
  keeps its exact parser and authentication semantics, and unknown revisions
  fail closed without decoder fallback. This exception does not permit changing
  an existing revision or freezing experimental encodings implicitly.
- Preserve CLI commands, flags, exit behavior, stdout/stderr roles, JSON fields,
  configuration, and public Rust APIs unless the SemVer impact is documented.
- Treat GUI, SFX, hybrid recipients, cascade/LCO, recovery, approvals, policies,
  and server-side web processing as experimental unless project status is
  explicitly changed. Never claim audit or absolute security.

## Documentation and versions

Keep `README.md` and `README_ja.md` behaviorally synchronized. Commands must
match `lvau-cli --help`; download names must match release workflow assets.
Update all workspace crate versions together. Use SemVer based on CLI, format,
Rust API, config, GUI persistence, server API, and documented install behavior,
then add the corresponding `CHANGELOG.md` and migration entry.

## OCI and web rules

Do not add OCI SDKs to `lvau-core` merely because the service runs on OCI. If a
future component calls OCI control-plane APIs, prefer the official SDK and
workload identity (instance/resource principals), configurable region and
timeouts, bounded exponential backoff with jitter for 429/transient 5xx,
`opc-retry-token` for retryable creates, complete `opc-next-page` pagination,
`opc-request-id` diagnostics without secrets, ETag/`if-match` where supported,
and bounded work-request waiters. Unit tests must use mocks/fixtures and normal
CI must not create cloud resources.

Browser code must never contain cloud credentials. Document whether a web flow
is local, proxied, or server-processed; do not call server processing E2EE or
zero-knowledge. Keep upload limits consistent across UI, proxy, and API.

## Change discipline

Respect existing uncommitted work. Prefer a failing regression test before a
fix and avoid unrelated refactors. Before handing off, report exact commands,
results, residual risks, and platform limitations.

Never commit, push, create a tag/release, or deploy the site/API without
explicit user authorization. A release tag triggers publication.

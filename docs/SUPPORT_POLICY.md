# Lvau support, deprecation, and emergency-disable policy

This policy covers the pre-1.0 experimental phase. It does not promise
production support and does not claim any independent security review.

## Reader support

- Format v1 and v2 readers are preserved exactly. Historical fixtures for
  tagged releases v0.2.0, v0.2.1, v0.3.0, v0.4.0, and v0.5.0 are checked by
  `crates/lvau-core/tests/historical_compatibility.rs`. There is no v0.1.0
  fixture because no official v0.1.x release binary was published.
- Experimental v3 revisions (legacy password, A3, A4) are read by the current
  CLI. Unknown `(format_version, envelope_revision)` tuples, suite IDs, KDF
  IDs, and slot tags fail closed without decoder fallback.

## Writer defaults

- Format v2 remains the default writer. Every v3 payload suite, recipient
  suite, and revision upgrade is explicit opt-in (`--format v3`, `--suite`,
  `--recipient-suite`, `rekey convert-a3`), so a compromised or deprecated
  experimental suite is never selected silently.

## Deprecation rules

- A published (post-freeze) encoding is never edited in place. A changed
  authentication semantic, key schedule, nonce rule, AAD layout, slot encoding,
  suite ID meaning, JSON field, or error contract requires a new version and
  migration notes in `CHANGELOG.md` and the format documents.
- Experimental pre-freeze encodings may still change; such changes are
  recorded in `CHANGELOG.md` with the affected suite and revision.

## Emergency suite disablement

There is no runtime kill-switch: disablement works through the following
properties, which are tested, not assumed:

1. Unknown suite/KDF/slot IDs are rejected before key derivation or payload
   work (see the fixed rejection tests around each v3 revision).
2. Writers never fall back to another suite; an unavailable or rejected suite
   is a hard error, not a downgrade.
3. New write paths stay behind explicit flags, so operators stop selecting a
   suite by no longer passing its flag.

If a post-freeze suite must be withdrawn, it is removed from the writer first
while its reader is kept for migration, and the withdrawal is announced in
`CHANGELOG.md` and the release notes with affected suite IDs and versions.

# Security Policy

## Private reporting

Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, log, or test fixture. Open a
[private GitHub security advisory](https://github.com/lasder-ca/lvau/security/advisories/new)
with:

- affected versions and environment;
- the smallest safe reproduction;
- expected and observed behavior;
- confidentiality, integrity, or availability impact; and
- a proposed mitigation, if known.

Do not include real passwords, private keys, tokens, user files, OCIDs, or
production service data. If the advisory form is unavailable, contact the
maintainers through the current
[lasder-ca profile](https://github.com/lasder-ca)
without publishing exploit details.

## Scope

Reports about cryptographic integration, nonce/key/KDF handling, envelope and
bundle parsing, output-file safety, key permissions, secret leakage, CLI/GUI
security boundaries, or release artifacts are welcome. Resource-exhaustion
findings are in scope when a bounded input can cause disproportionate impact.

Weak user-selected passwords, endpoint compromise, and upstream dependency
bugs are generally outside Lvau's direct control, but please report an
Lvau-specific unsafe interaction or missing mitigation privately.

The latest release and the default development branch receive priority.
Historical pre-1.0 releases may require migration rather than an in-place fix.

## Audit and maturity status

Lvau has not been formally audited by an independent third party. Its format is
not stable before 1.0, and hybrid recipients, cascade/LCO profiles, GUI, SFX,
recovery, approval/policy workflows, and server processing are experimental.
Use [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) to evaluate whether those
boundaries fit your use case.

## Key and password files

Lvau creates private key and recovery-share files with owner-only permissions
on Unix where supported and applies Windows ACL hardening to private identity
keys. Unix `--password-file` and `--seed-file` inputs must be regular files with
no group/world permission bits. Platform backup, administrator access, and
filesystem semantics can still bypass application-level permissions.

## Coordinated disclosure

Please limit testing to data and systems you are authorized to use and allow
maintainers reasonable time to investigate before public disclosure. Reporter
credit will be coordinated through the private advisory.

# Threat Model

Lvau is experimental encryption software and has not received a formal,
independent security audit. This model describes intended boundaries, not a
security certification.

## Intended protections

With a strong, secret password or an uncompromised recipient private key, a v2
capsule is intended to protect file contents at rest and detect payload
modification, truncation, trailing ciphertext, and frame reordering. V2 AEAD
also commits to the header, plaintext length, nonces, content type, public
label, public metadata, and policy-override flag.

Password resistance is limited by password entropy and the selected Argon2id
profile. Recipient encryption wraps a random file key for experimental hybrid
X25519 + ML-KEM-768 recipients. Ed25519 author signatures and approval seals can
authenticate their signed statements when verified with public keys obtained
through a trusted channel.

Bundle manifests and file names are encrypted. The extractor validates paths,
bounds, overlaps, case collisions, hashes, and symlink overwrite behavior
before writing file data.

## Assumptions

- The operating-system RNG, cryptographic crates, Rust toolchain, build
  artifacts, and update channel are trustworthy.
- The endpoint is not compromised while secrets are entered or plaintext is
  processed.
- Users independently authenticate signing/verification keys and protect
  private keys, passwords, seed files, recovery shares, and local policies.
- Outputs are written to trusted local directories. Path-based temporary-file
  publication does not defend against a concurrent process that can mutate the
  destination directory or replace a staging pathname. Extraction into a
  concurrently attacker-controlled directory is also not supported.

## Important limitations

- Root/administrator access, malware, debuggers, keyloggers, malicious editors,
  swap, hibernation, crash dumps, and compromised terminals can expose secrets.
- `zeroize` is used where practical, but complete erasure across allocators,
  copies, operating-system buffers, GUI widgets, and hardware is not guaranteed.
- File names, lengths, timing, access patterns, envelope fields, recipient
  count, KDF settings, and an optional public label may leak information.
- V1 files are legacy: only their header is committed through payload AAD.
  Migrate by decrypting and re-encrypting with 0.4.0 or later.
- A public envelope hash is unkeyed. It does not authenticate an unsigned
  capsule by itself.
- Signature or approval presence does not establish identity. Approvals are
  advisory and do not gate decryption; policy lint does not establish signer
  trust.
- Recovery shares protect the split secret only when shares are stored and
  transported independently. Recovery metadata does not prove share
  availability.
- Cascade profiles, LCO, hybrid recipients, SFX, GUI workflows, and recovery
  features are experimental. LCO is obfuscation, not another cipher.
- Experimental v3 HPKE Base mode uses only X25519 from existing hybrid key
  files, is not post-quantum, and does not authenticate the sender. Recipient
  key IDs identify key material, not its owner. Password-v3 root-key rotation
  creates a newly encrypted copy; it cannot revoke old copies or credentials
  already obtained. HPKE recipient-set changes require full decrypt/re-encrypt
  for legacy A3 files. Revision A4 has a root-key-authenticated mutable slot
  table; its ML-KEM-768 slot uses an anonymous KEM followed by a Lvau-specific
  AEAD root wrap, not HPKE, and does not authenticate the sender. The current
  RustCrypto `ml-kem` implementation has not been independently audited, and A4
  has not completed independent format review. V3 A4 has no signatures or
  approvals; its header HMAC proves possession of the file root key, not author
  identity.
- Ed25519 and X25519 are not post-quantum. The hybrid recipient mode includes
  ML-KEM-768 but has not been independently reviewed as an integrated design.
- Bundle contents use bounded streaming buffers, while the authenticated
  manifest is held in memory up to the documented 16 MiB limit. Extraction
  authenticates and stages every entry before publishing files, then commits
  each file atomically; it is not an all-or-nothing directory transaction, so a
  later commit failure may leave earlier files published. Do not extract into a
  concurrently attacker-controlled directory: path checks do not pin parent
  directory handles against replacement races.
- Lvau does not provide plausible deniability, steganography, full-disk
  encryption, filesystem mounting, secure deletion, rollback protection, or a
  network transport protocol.

## Web and server API

The `lattes.jp` web workflow sends the file and password through a Vercel
Function to the OCI-hosted `lvau-api`. It is not end-to-end encrypted or
zero-knowledge: those servers can observe plaintext/password material while
processing a request. Use the local CLI/GUI when server access is outside the
trust boundary. Browser limits and server limits are availability controls,
not confidentiality guarantees.

## Primitive inventory

The stable default payload uses XChaCha20-Poly1305. Password derivation uses
Argon2id v1.3; subkeys use HKDF-SHA256; signatures use Ed25519. Experimental
profiles additionally use AES-256-GCM, X25519, ML-KEM-768, and reversible LCO
transformation. Lvau does not claim that combining more primitives is
automatically stronger.

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).

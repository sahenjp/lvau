# `.lvau` Envelope Format

This document describes the format accepted by `lvau-protocol` and
`lvau-core` 0.5.0. The format is experimental and is not stable before 1.0.
Do not implement an independent reader from this document alone; postcard
encoding is tied to the Rust data model and serialization version.

## Physical layout

Every capsule is:

1. a four-byte little-endian `u32` envelope length;
2. exactly that many bytes of postcard-encoded `Envelope` data; and
3. the encrypted payload frames.

The common reader rejects an empty envelope, envelopes larger than 1 MiB,
truncated input, trailing bytes inside the encoded envelope, invalid magic,
unsupported versions, invalid recipient/KDF combinations, and invalid nonce
layouts. No payload algorithm other than the three file-encryption algorithms
listed below is accepted.

Experimental single-file format v3 uses separate protocol types and a strict
version/revision dispatch path; it is not another `Envelope` encoding described
below. Format v2 remains the default writer. The legacy password envelope and
X25519 HPKE revision are documented in the [v3 draft](FORMAT_V3_DRAFT.md); neither
is frozen or independently reviewed.

```rust
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub plaintext_len: u64,
    pub nonce: [u8; 24],
    pub secondary_nonce: Option<[u8; 12]>,
    pub aad_hash: [u8; 32],
    pub metadata: Vec<u8>,
    pub content_type: Option<ContentType>,
    pub signature: Option<EnvelopeSignature>,
    pub public_label: Option<String>,
    pub approvals: Vec<ApprovalSignature>,
    pub release_metadata: Option<ReleaseMetadata>,
    pub policy_overridden: bool,
    pub recovery_metadata: Option<Vec<u8>>,
}
```

`None` content type means `SingleFile` for legacy compatibility.

## Header and versions

```rust
pub struct EnvelopeHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub profile: SecurityProfile,
    pub algorithm: AlgorithmId,
    pub kdf: Option<KdfParams>,
    pub recipients: Vec<Recipient>,
}
```

- `magic` is the ASCII byte sequence `LVAU`.
- 0.4.0 and later write format version `2` and read versions `1` and `2`.
- There must be 1 to 64 recipients. Password and key-pair recipients cannot be
  mixed in one capsule.
- Password capsules must have the exact Argon2id tuple for their profile.
  Key-pair capsules must not have KDF parameters.

| Format | Written by | Reader behavior | Payload commitment |
| --- | --- | --- | --- |
| legacy six-field v1 | 0.2.x | decoded through an explicit legacy structure | header only |
| extended v1 | 0.3.x | accepted for backward compatibility | header only |
| v2 | 0.4.0+ | current write format | fields listed below |

Version 1 remains readable, but its plaintext length, nonces, metadata,
content type, public label, and workflow fields are not included in the AEAD
commitment. Decrypt and re-encrypt with 0.4.0 or later to migrate to v2. This
is reader compatibility, not a promise that older binaries can read v2 files.

## Version 2 payload commitment

For v2, `aad_hash` is SHA-256 over the domain separator
`"Lvau payload AAD v2\0"` followed by the postcard encoding of:

- the complete `EnvelopeHeader`;
- `plaintext_len`;
- the XChaCha base nonce and optional AES base nonce;
- `metadata`;
- `content_type`;
- `public_label`; and
- `policy_overridden`.

The reader recomputes this value before decryption. Every AEAD payload frame
uses `aad_hash || chunk_index_le_u64` as additional authenticated data. Thus a
successful v2 decryption authenticates the committed public fields, frame
position, and payload.

The following workflow annotations are deliberately outside the payload AAD:
`signature`, `approvals`, `release_metadata`, and `recovery_metadata`. An
author signature or approval created after those fields are attached may cover
them, but their mere presence is not authentication. Consumers must verify the
relevant signature with an independently trusted public key.

For v1, `aad_hash` is SHA-256 of only the postcard-encoded header. Preflight
reports a warning for this weaker legacy binding.

## Payload frames and nonces

Payloads are divided into 1 MiB chunks and processed in batches of at most 32
chunks. For each global `u64` chunk index, its little-endian bytes are XORed
into the first eight bytes of each applicable base nonce. The index is also
included in AAD, preventing frame reordering or reuse at another position.

| Algorithm | Profiles | Per-frame authentication overhead |
| --- | --- | ---: |
| `XChaCha20Poly1305` | `fast`, `balanced`, `archive` | 16 bytes |
| `CascadeAesGcmXChaCha` | `paranoid` | 32 bytes |
| `TripleCascadeAesXChaChaLco` | `extreme` | 32 bytes |

Cascade and LCO profiles are experimental. LCO is reversible obfuscation and
is not an additional cryptographic security boundary.

V2 represents an empty plaintext with one authenticated empty frame. The v2
reader rejects truncated frames, a plaintext-length mismatch, and ciphertext
bytes after the expected final frame. V1 empty capsules without a frame remain
accepted for compatibility.

## Password KDF and file-key wrapping

Password encryption derives a 32-byte wrapping key with Argon2id v1.3 and a
random 16-byte salt, then wraps a random 32-byte file-encryption key with
XChaCha20-Poly1305. The wrapped key is exactly 48 bytes.

| Profile | `m_cost` KiB | `t_cost` | `p_cost` |
| --- | ---: | ---: | ---: |
| `fast` | 16,384 | 1 | 1 |
| `balanced` | 65,536 | 2 | 1 |
| `archive` | 262,144 | 3 | 2 |
| `paranoid` | 1,048,576 | 4 | 4 |
| `extreme` | 1,048,576 | 4 | 4 |

The salt and all nonces are generated from the operating-system RNG for each
new encryption. New encryptions reject an empty password or structured-secret
seed.

## Hybrid recipients

`X25519MlkemHybrid` recipient slots contain an ephemeral X25519 public key, an
ML-KEM-768 ciphertext, and a 48-byte wrapped file key. The two shared secrets
are combined using HKDF-SHA256 before file-key unwrapping. Decryption tries all
compatible recipient slots instead of assuming the first slot belongs to the
provided key. This mode is experimental and is not a substitute for an
independent security review.

## Bundle payload

For `ContentType::Bundle`, the decrypted bytes contain:

1. a four-byte little-endian manifest length;
2. exactly one postcard-encoded `BundleManifest`; and
3. file contents at the offsets declared by the manifest, with optional
   padding introduced by the selected padding profile.

Each entry has a portable relative path, `u64` size and offset, and BLAKE3
content hash. Before extraction, the reader validates every manifest entry,
including integer overflow, bounds, overlapping non-empty ranges, duplicate or
case-colliding paths, absolute paths, parent traversal, and content hashes.
Symlinks in the source are rejected unless explicitly allowed. Extraction
checks that resolved parents remain inside the destination and refuses existing
outputs unless `--force` is used. Even with `--force`, an existing
symlink/reparse point, non-regular file, or file with multiple hard links is
rejected rather than truncated. The current manifest represents regular files
only and never creates symlinks or hardlinks.

Unlike ordinary single-file encryption, current bundle packing, listing,
verification, and extraction use a complete decrypted bundle buffer. This is a
known scalability limitation; do not assume constant memory for large bundles.

## Author signatures and approvals

V2 author signatures use Ed25519 and a versioned domain separator. They cover
the envelope (with the signature bytes cleared and approvals removed) plus all
ciphertext, including the stored signer fingerprint, timestamp, and comment.
Approvals are independent so they can be appended without invalidating an
author signature.

A v2 approval covers the public envelope with all approvals removed, all
ciphertext, the approving-key fingerprint, and its comment. V1 author and
approval verification retain the historical statement for compatibility; v1
approvals cover only `aad_hash` and therefore provide weaker evidence.

Neither an author signature nor an approval establishes identity or trust on
its own. Verification must use a public key obtained through a trusted channel.
Approval count is advisory metadata and does not gate decryption.

## Public information

The envelope length and envelope fields are public. Depending on the capsule,
this reveals the format version, algorithm, profile, KDF costs and salt,
recipient count and recipient encapsulation data, base nonces, plaintext
length, ciphertext length, optional public label, and workflow annotations.
Bundle paths and contents are inside the encrypted payload unless the user
copies them into a public label or other public metadata.

## Change policy

Before 1.0, forward compatibility is not guaranteed. Any format change must
update the version, decoder bounds, compatibility tests, this document, and
`CHANGELOG.md`. A new writer must not silently reinterpret existing version
numbers. Security fixes may require a new format version even when the CLI
remains source-compatible.

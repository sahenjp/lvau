# Lvau format v3 draft (experimental)

This document describes three experimental single-file v3 envelope revisions:
the original password envelope (implicit legacy revision, supporting payload
suites `LV3-XC20P` and `LV3-AESGCMSIV-XC20P`), the X25519 HPKE-recipient
envelope (`0xA3`, `LV3-XC20P` only), and the mutable root-wrap envelope
(`0xA4`, `LV3-XC20P` and `LV3-AESGCMSIV-XC20P`) supporting password, X25519
HPKE, and pure ML-KEM-768 slots. V3 is **not frozen, independently reviewed,
or a compatibility promise**. V2 remains the default writer. V3 bundles and
ML-DSA recipients are absent.

## Physical layout

Each revision begins with a four-byte little-endian envelope length, exact
postcard envelope bytes, then ciphertext frames. The legacy password envelope
is limited to 256 bytes; revision `0xA3` to 8192 bytes; revision `0xA4` to
96 KiB. Decoders dispatch by the version/revision tuple before allocation,
require exact canonical postcard encoding, and fail closed on unknown revisions
without trying another decoder.

## Legacy password revision

The original v3 password envelope has no explicit revision byte. Its exact
`V3Envelope` fields remain:

1. `magic: [u8; 4]` = `LVAU`
2. `version: u16` = 3
3. `suite_id: u8` = 1 (`LV3-XC20P`) or 2 (`LV3-AESGCMSIV-XC20P`, layered,
   password revision only)
4. `profile_id: u8` = 0 Fast, 1 Balanced, 2 Archive, 3 Paranoid, 4 Extreme
5. `kdf_id: u8` = 1 (Argon2id v1.3)
6. `salt: [u8; 16]`
7. `wrapping_nonce: [u8; 24]`
8. `encrypted_file_root_key: [u8; 48]`
9. `payload_base_nonce: [u8; 24]`
10. `plaintext_len: u64`

Unknown suite, profile, or KDF IDs are rejected before KDF work. Profile costs
are Fast `(16384,1,1)`, Balanced `(65536,2,1)`, Archive `(262144,3,2)`, and
Paranoid/Extreme `(1048576,4,4)`, expressed as Argon2 `m,t,p`.

Legacy password root-key wrapping:

A random 32-byte file root key is wrapped by XChaCha20-Poly1305. The wrapping
key is HKDF-SHA256 with salt/domain
`Lvau v3 password root wrapping\0`, IKM equal to the Argon2id master key, info
`LV3-XC20P`, and 32-byte output.

Wrap AAD is `Lvau v3 password root AAD\0 || postcard(V3RootWrapAad)`, where
`V3RootWrapAad` contains `magic, version, suite_id, profile_id, kdf_id, salt,
wrapping_nonce, payload_base_nonce, plaintext_len` in that order. The wrapped
root key is excluded to avoid a cycle.

## Envelope commitment and payload

For the legacy password revision, the existing v3 `EnvelopeCommitment` subkey
is derived from the root key for suite `LV3-XC20P`. HKDF-SHA256 then uses salt/domain
`Lvau v3 envelope commitment\0`, that subkey as IKM, and the exact serialized
`V3Envelope` bytes as info to produce the 32-byte envelope commitment.

Payload frames use the existing v3 `PayloadSingle` key,
`derive_xchacha_nonce(..., Single, index)`, `V3ChunkDescriptor`, and canonical
chunk AAD. Chunks are fixed at 1 MiB except the last. There are no frame length
headers: `plaintext_len` determines each plaintext length and the corresponding
ciphertext length is plaintext plus the 16-byte tag. Empty input has one
authenticated empty frame. Decoders reject missing frames, bad tags, declared
length mismatch, and every trailing byte after the expected final frame.

## Fixed vector

The following deterministic inputs are used by
`crypto::suite::v3::file::tests::v3_envelope_wrap_commitment_and_frame_match_fixed_vectors`:

- envelope fields: `LVAU`, version `3`, suite `1`, profile `0`, KDF `1`, salt
  `10` repeated 16 times, wrapping nonce `20` repeated 24 times, wrapped root
  key `30` repeated 48 times, payload nonce `40` repeated 24 times, and length
  `42`;
- root key: `a5` repeated 32 times;
- chunk: index `0`, final flag `1`, plaintext `vector`.

The exact postcard envelope bytes are:

```text
4c56415503010001101010101010101010101010101010102020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040402a
```

The exact root-wrap AAD, including its domain prefix, is:

```text
4c7661752076332070617373776f726420726f6f7420414144004c56415503010001101010101010101010101010101010102020202020202020202020202020202020202020202020204040404040404040404040404040404040404040404040402a
```

The envelope commitment is
`5bcfdc10143274765c441bcc3f1c879461348341d8891f70ee8025cd4b82baea`; the
`LV3-XC20P` ciphertext for the chunk is
`9adca79709a2658834384ae5f79469fd82254b8eebb1`.

## Layered payload suite `LV3-AESGCMSIV-XC20P` (password and A4 revisions)

The legacy password envelope accepts `suite_id = 2` for the layered suite:
AES-256-GCM-SIV inner encryption followed by XChaCha20-Poly1305 outer
encryption. It is explicit opt-in (`--format v3 --suite lv3-aesgcmsiv-xc20p`);
the default writer stays single-layer `LV3-XC20P`, and revisions `0xA3`/`0xA4`
reject suite 2. This suite never shipped before, so no existing reader can
misinterpret it, and older readers fail closed on the unknown suite identifier.

Per-chunk construction, in fixed order:

1. inner: AES-256-GCM-SIV over the plaintext with key
   `derive_subkey(root, suite, PayloadInnerAes256GcmSiv)`, 12-byte nonce
   `derive_layered_inner_nonce(base24, index)` HKDF-derived from the stored
   24-byte `payload_base_nonce` under the layered-suite/inner-layer domain, and
   AAD `chunk_aad(suite, Inner, commitment, descriptor, inner_len = 0,
   ciphertext_len = plaintext_len + 16)`;
2. outer: XChaCha20-Poly1305 over the inner ciphertext with key
   `derive_subkey(root, suite, PayloadOuterXChaCha20Poly1305)`, nonce
   `derive_xchacha_nonce(base24, suite, Outer, index)`, and AAD
   `chunk_aad(suite, Outer, commitment, descriptor, inner_len,
   ciphertext_len = inner_len + 16)`.

Decryption authenticates the outer layer first and only then the inner layer;
plaintext is released solely after both layers authenticate. Total per-chunk
overhead is 32 bytes. The root-wrap key info (`LV3-AESGCMSIV-XC20P`), envelope
commitment subkey, both nonces, and both AADs bind the suite identifier, so
relabelling a file between suites breaks root-key unwrapping and frame
authentication. Tested by
`crypto::suite::v3::tests::layered_chunk_fixed_vector` (nonce, AAD, and
ciphertext vectors), cross-suite encrypt/decrypt rejection tests, file-level
tamper/truncation/suite-relabelling tests, and a CLI roundtrip test.

`rekey rotate-root` preserves the suite through full re-encryption.
Frame-preserving `rekey` slot updates carry the source suite (single or layered)
into the A4 envelope and copy frame bytes unchanged; `rekey convert-a3` stays
`LV3-XC20P`-only because revision `0xA3` never writes the layered suite.

## X25519 HPKE-recipient revision `0xA3`

The explicit revision marker follows postcard `version = 3`. The old password
envelope's next byte is its legacy payload-suite ID and is parsed only by the
legacy decoder. Revision `0xA3` has these `V3HpkeEnvelope` fields in order:

1. `magic: [u8; 4]` = `LVAU`
2. `version: u16` = 3
3. `envelope_revision: u8` = `0xA3`
4. `payload_suite_id: u8` = 1 (`LV3-XC20P`)
5. `payload_base_nonce: [u8; 24]`
6. `plaintext_len: u64`
7. `recipients: Vec<V3HpkeRecipient>`

The recipient vector contains 1 to 64 entries, sorted by unsigned
`(recipient_suite_id, key_id)` byte order with duplicates rejected. The only
suite ID currently accepted is 1, mapping to RFC 9180 Base mode
DHKEM(X25519, HKDF-SHA256) (`kem_id = 0x0020`), HKDF-SHA256 (`kdf_id = 0x0001`),
and ChaCha20-Poly1305 (`aead_id = 0x0003`). Each slot stores the suite ID, a
32-byte algorithm-qualified key ID, a 32-byte HPKE encapsulated key, and a
48-byte ciphertext wrapping the 32-byte file root key. The CLI obtains the
X25519 public key from the existing hybrid key file; this revision does not use
its ML-KEM component.

The key ID is SHA-256 over:

```text
"Lvau v3 recipient key ID\0"
|| recipient_suite_id_u8
|| kem_id_be_u16 || kdf_id_be_u16 || aead_id_be_u16
|| canonical_X25519_public_key_32
```

This public identifier does not authenticate the key owner's identity. RFC
9180's X25519 serialization/deserialization accepts the 32-byte string as-is;
Lvau deliberately adds a stricter canonical-encoding profile that requires the
high bit clear and the field element below `2^255 - 19`. This narrows wire
interoperability and is a Lvau restriction, not an RFC 9180 requirement. The
HPKE backend rejects non-contributory all-zero DH results as required by RFC
9180.

The HPKE application context commits to this fixed-field core serialized with
postcard:

```text
magic || version || envelope_revision || payload_suite_id
|| payload_base_nonce || plaintext_len
```

`core_commitment = SHA-256("Lvau v3 HPKE payload core\0" || postcard(core))`.
HPKE `info` is the domain `Lvau v3 HPKE root-wrap info\0` followed by
`core_commitment || recipient_suite_id || kem_id_be_u16 || kdf_id_be_u16 ||
aead_id_be_u16 || key_id`. HPKE AAD uses the same fixed suffix with the distinct
domain `Lvau v3 HPKE root-wrap AAD\0`. The 32-byte `enc` is additionally bound by
RFC 9180's KEM context.

The payload commitment is root-key-derived over the exact serialized complete
envelope, including every recipient slot. Slot removal, insertion, reordering,
or mutation therefore makes payload-frame authentication fail. Adding or
removing a recipient requires full decrypt/re-encrypt; mutable-table rewrap is
not supported. The CLI's `rekey rotate-root` currently accepts only the legacy
password revision. HPKE Base mode does not authenticate the sender, and this
X25519-only recipient suite is not post-quantum.

## RFC 9180 recipient-open vector

The test suite opens RFC 9180 Appendix A.2.1 using the exact X25519 Base-mode
vector and asserts the plaintext `Beauty is truth, truth beauty`:

```text
skRm: 8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb
enc:  1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a
info: 4f6465206f6e2061204772656369616e2055726e
aad:  436f756e742d30
ct:   1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28
```

## Mutable root-wrap revision `0xA4`

Revision `0xA4` separates payload authentication from a mutable root-wrap slot
table. It is a new wire revision; neither legacy password-v3 nor HPKE revision
`0xA3` changes meaning. Its envelope is limited to 96 KiB. The postcard fields
are encoded in this order:

1. `magic: [u8; 4]` = `LVAU`
2. `version: u16` = 3
3. `envelope_revision: u8` = `0xA4`
4. `payload_suite_id: u8` = 1 (`LV3-XC20P`) or 2 (`LV3-AESGCMSIV-XC20P`)
5. `payload_base_nonce: [u8; 24]`
6. `plaintext_len: u64`
7. `payload_binding: [u8; 32]`
8. `slots: Vec<V3MutableSlot>`
9. `header_authenticator: [u8; 32]`

The slot enum has fixed postcard variant tags: 0 Password, 1 X25519 HPKE, 2
ML-KEM-768, 3 Hybrid-X25519-MLKEM-768. Slots are strictly ordered by
`(variant_tag, key_id)`; there is at
most one password slot and 0–64 recipient slots, with at least one total slot.
Thus a password-only envelope is valid and up to 65 total slots are serialized.
Unknown enum tags, duplicate/unsorted slots, unknown KDF/suite IDs,
over-limit counts, noncanonical encodings, and oversized envelopes are rejected
before key derivation or payload work.

Recipient key-ID compatibility rules: every key ID is SHA-256 over the domain
`Lvau v3 A4 recipient key ID\0`, one slot-tag byte selecting the algorithm
composition (`0x01` X25519-HPKE with KEM/KDF/AEAD IDs, `0x02` ML-KEM-768 with
the encapsulation key, `0x03` hybrid with both public components), and the
canonical public bytes. Key IDs never cross tags: a hybrid private key does not
match pure X25519 or ML-KEM slots and vice versa. Unknown slot tags fail closed
without reinterpretation.

### Payload binding and table authentication

The immutable payload core is:

```text
magic || version || envelope_revision || payload_suite_id
|| payload_base_nonce || plaintext_len
```

For newly encrypted A4 files, `payload_binding` is HKDF-SHA256 over
`postcard(core)`, with the root-derived `EnvelopeCommitment` subkey for the
envelope's own payload suite and salt/domain
`Lvau v3 A4 payload binding\0`. Suite-1 files therefore keep their historical
binding byte-for-byte, while layered files bind the layered suite through both
the subkey and the suite-tagged core. Existing password-v3 files migrated
to A4 carry their original full-envelope commitment byte-for-byte; this allows
the existing ciphertext frames to remain unchanged. Each frame's AAD continues
to authenticate the binding.

After unwrapping the root key, the reader verifies the header authenticator
before processing payload frames:

```text
K_header = HKDF-SHA256(root_key,
    salt = "Lvau v3 A4 header key\0",
    info = "Lvau v3 A4 header authenticator HMAC-SHA256\0")
header_authenticator = HMAC-SHA256(K_header,
    "Lvau v3 A4 envelope authenticator\0"
    || postcard(all envelope fields except header_authenticator))
```

The MAC covers the immutable payload fields, payload binding, every slot, and
all root-wrap ciphertexts. Rewrapping can therefore update slots and recompute
the MAC without changing frame AAD or ciphertext. This is an authenticated
mutable table for holders of the file root key; it is not a signature and does
not authenticate the sender or prevent rollback to an older valid file.

Because `K_header` is derived from the root key, an A4 reader cannot verify this
MAC before opening a root-wrap slot. It selects at most one candidate slot from
the supplied password or algorithm-qualified private-key ID, opens that wrap,
then verifies the complete table MAC before any payload frame is processed; it
does not try alternate slots after a failed selected wrap. GitHub issue #13's
literal “verify the table authenticator before any slot is attempted” ordering
cannot be met by a root-key-derived MAC. Meeting that literal requirement would
need an independent public verifier/trust anchor and a different format design.

V3 A4 currently has no signature, approval, or release-metadata field. Its
rewrap commands do not produce or preserve a signature statement. A future
signature revision must explicitly choose whether signatures cover the mutable
slot table, immutable payload binding, or both; current header authentication
does not establish an author's identity.

### Root-wrap slots

**Password, tag 0:** one Argon2id v1.3 slot using the existing fixed profiles,
fresh 16-byte salt, fresh 24-byte XChaCha nonce, and a 48-byte encrypted root
key. The wrapping key uses HKDF-SHA256 with domain
`Lvau v3 A4 password root wrapping\0` and suite-qualified info (`LV3-XC20P` for
suite-1 files, `LV3-AESGCMSIV-XC20P` for layered files; suite-1 wraps are
unchanged). AAD binds the A4 payload core, payload binding, slot tag,
profile/KDF IDs, salt, and nonce.
Profile costs are validated before Argon2 work; parameter updates use a named
profile rather than accepting arbitrary attacker-controlled costs.

**X25519 HPKE, tag 1:** uses the same RFC 9180 Base-mode suite as revision A3
(DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305) and wraps the file
root key. A4-specific `info` and AAD domain-separate the slot and bind the A4
slot context/key ID; the HPKE KEM context binds its `enc`. This remains standard
HPKE for the inner key-wrap operation with Lvau-specific file context.

**ML-KEM-768, tag 2:** uses the ML-KEM-768 parameter set from NIST FIPS 203, not
an X25519+ML-KEM hybrid and not HPKE. A slot carries an algorithm-qualified
32-byte key ID, fixed 1088-byte ML-KEM ciphertext, fresh 24-byte XChaCha nonce,
and a 48-byte AEAD ciphertext wrapping the 32-byte root key. The KEM shared
secret is expanded with HKDF-SHA256 under the A4 ML-KEM root-wrap domain; AAD
binds the A4 slot context, key ID, KEM ciphertext, and nonce. ML-KEM implicit
rejection yields a fallback shared secret for correctly sized malformed
ciphertexts, so the root-wrap AEAD must fail before any file key is accepted.
The key ID hashes `Lvau v3 A4 recipient key ID\0 || 0x02 ||
serialized_ML-KEM-768_encapsulation_key`. The CLI currently reads this component
from the existing hybrid key file; it does not use that key's X25519 component
for this suite. The slot tag and key-ID domain prevent interpreting it as the
X25519 HPKE suite.

The RustCrypto `ml-kem` 0.3.2 crate describes itself as an FIPS 203
implementation, but also states that it has not been independently audited.
The NIST publication currently carries a planning note about a future revision;
recheck its errata before any format promotion. A test runs the NIST ACVP
ML-KEM-768 encapsulation vector (`encapDecap` internal projection, vector group
2, case 26) against the crate's deterministic test API.

Standards and vector sources: [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final), and the
[NIST ACVP-Server ML-KEM encap/decap internal projection at commit
65370b8](https://github.com/usnistgov/ACVP-Server/blob/65370b861b96efd30dfe0daae607bde26a78a5c8/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json).

**Hybrid X25519+ML-KEM-768, tag 3 (experimental):** dual-wrap construction. The
slot carries one hybrid key ID plus a complete X25519-HPKE wrap and a complete
ML-KEM-768 wrap of the same file root key, each built with the existing
per-suite primitives under the shared A4 slot context. The hybrid key ID hashes
`Lvau v3 A4 recipient key ID\0 || 0x03 || canonical_X25519_public_key_32 ||
serialized_ML-KEM-768_encapsulation_key`. Either private component whose
recomputed hybrid ID matches opens the slot by trying its own inner wrap first
and then the other component's wrap; a wrong key or mutated hybrid ID fails
without revealing which component mismatched. This is not a KEM combiner:
breaking either component KEM exposes the root key, so the hybrid composition
stays experimental until its construction is stable and independently reviewed.
Creation, add/remove, and direct file encryption all support both payload
suites; CLI selects it with `--recipient-suite hybrid-x25519-mlkem`.

### A4 binding/authenticator/frame vector

`crypto::suite::v3::mutable_file::tests::mutable_envelope_binding_header_and_frame_fixed_vector`
uses root key `a5` repeated 32 times, nonce `40` repeated 24 times, plaintext
`vector`, and one synthetic password slot (profile 0, KDF 1, salt `10` repeated
16 times, wrap nonce `20` repeated 24 times, wrapped-root bytes `30` repeated 48
times). It checks the new payload binding, slot context, header HMAC, exact
postcard A4 envelope bytes, and payload frame:

```text
payload_binding: 6567498203eba28eface47d7b903372c3c6711e1800db616755e368758739284
slot_context:    5d6cab7523280e9b1eabecca7992a7b2a929d30c891cd836d0b4079a6feac0f8
header_mac:      59e235b6cde019d907c7fa83fd200e7625bf3f41fa562f48d8859ff2ff00ae8d
envelope:        4c56415503a401404040404040404040404040404040404040404040404040066567498203eba28eface47d7b903372c3c6711e1800db616755e368758739284010000011010101010101010101010101010101020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303059e235b6cde019d907c7fa83fd200e7625bf3f41fa562f48d8859ff2ff00ae8d
frame:           9adca79709a22534e1f0633a52ba31b8386198515b4a
```

This is an A4 composition vector, not an HPKE vector or an ML-KEM KEM vector;
the latter use their respective published test vectors above.

### Rewrap/update operations

`rekey add-recipient` converts a legacy password-v3 file to A4 or adds a slot to
an A4 file, using either an existing password or the private key for a retained
A4 slot. `rekey remove-recipient` removes the named X25519 HPKE, ML-KEM-768, or
hybrid slot from A4. If the credential used for the update is the slot being removed,
the command permits the update only if that same hybrid private key can open
another retained algorithm slot; otherwise the update is rejected. A password
credential remains usable when a recipient slot is removed. `rekey change-password` creates/replaces the password slot with a
fresh salt and nonce; it can use an existing recipient private key to add the
first password slot. Absent an explicit profile it preserves the current profile
or uses Balanced when adding a first password slot. Each operation first verifies
the old credential, header MAC where present, and every payload frame. It then
stages an A4 envelope and copies the encrypted frame bytes unchanged,
reopens/verifies the staged file with a surviving credential, syncs it, and
atomically persists it. The original file remains available if staging or
verification fails.

Rewrapping does not rotate the root key. Removing a slot cannot revoke an old
file copy, an already learned root key, or previously obtained plaintext.
`rekey rotate-root` remains full decrypt/re-encrypt and remains distinct from
these A4 updates. Revision A3 recipient tables are immutable in place.
`rekey convert-a3` creates a separate A4 artifact after authenticating the A3
source and every payload frame. It requires public keys covering every original
A3 slot (the supplied source private key's public key is included automatically),
creates fresh A4-specific wraps and a new header MAC, carries the exact A3
full-envelope commitment into `payload_binding`, and copies all encrypted frame
bytes unchanged. Missing original recipient keys cause refusal rather than
silent loss of access. The source A3 file remains unchanged; the converted A4
artifact contains only the explicitly covered destination recipients.

## Normative test vectors

These checked-in vectors pin the experimental encodings and must keep passing
unchanged; any intentional change is a format change, not an edit:

- Legacy password revision: `crypto::suite::v3::file::tests::v3_envelope_wrap_commitment_and_frame_match_fixed_vectors`.
- Layered chunk framing: `crypto::suite::v3::tests::layered_chunk_fixed_vector`.
- A3 recipient open: `crypto::suite::v3::hpke_file::tests::opens_rfc_9180_base_mode_x25519_chacha_vector` (RFC 9180 base-mode X25519/ChaCha20-Poly1305 vector).
- A4 envelope binding, header MAC, and frame codec: `crypto::suite::v3::mutable_file::tests::mutable_envelope_binding_header_and_frame_fixed_vector`.
- A4 ML-KEM-768 encapsulation: `crypto::suite::v3::mlkem::tests::mlkem_768_encapsulation_matches_nist_acvp_vector` (NIST ACVP `encapDecap` internal projection, group 2, case 26).
- A4 hybrid slot construction: `crypto::suite::v3::hybrid::tests::hybrid_slot_opens_with_either_component` and `hybrid_key_id_is_algorithm_and_key_separated` (composition and key-ID separation; wraps themselves are randomized), plus `crypto::suite::v3::mutable_file::tests::hybrid_envelope_roundtrip_in_both_payload_suites` for both payload suites.
- Historical readers: `crates/lvau-core/tests/historical_compatibility.rs` decrypts tagged release fixtures v0.2.0, v0.2.1, v0.3.0, v0.4.0, and v0.5.0. No official v0.1.x release binary exists, so v0.1.0 has no fixture; that gap is recorded in `docs/DEVELOPMENT_STATUS.md`.

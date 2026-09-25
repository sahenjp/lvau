use serde::{Deserialize, Serialize};

pub const V3_MAGIC: [u8; 4] = *b"LVAU";
pub const V3_VERSION: u16 = 3;
pub const V3_SUITE_XCHACHA20_POLY1305: u8 = 1;
pub const V3_KDF_ARGON2ID_V13: u8 = 1;
pub const V3_MAX_ENVELOPE_SIZE: usize = 256;
pub const V3_HPKE_ENVELOPE_REVISION: u8 = 0xA3;
pub const V3_HPKE_MAX_ENVELOPE_SIZE: usize = 8192;
pub const V3_HPKE_MAX_RECIPIENTS: usize = 64;
pub const V3_HPKE_RECIPIENT_SUITE_X25519_HKDF_SHA256_CHACHA20POLY1305: u8 = 1;
pub const V3_MUTABLE_ENVELOPE_REVISION: u8 = 0xA4;
pub const V3_MUTABLE_MAX_ENVELOPE_SIZE: usize = 96 * 1024;
pub const V3_MUTABLE_MAX_RECIPIENTS: usize = 64;
pub const V3_MUTABLE_MAX_SLOTS: usize = V3_MUTABLE_MAX_RECIPIENTS + 1;
pub const V3_MUTABLE_SLOT_PASSWORD: u8 = 0;
pub const V3_MUTABLE_SLOT_X25519_HPKE: u8 = 1;
pub const V3_MUTABLE_SLOT_MLKEM768: u8 = 2;
pub const V3_MLKEM768_CIPHERTEXT_SIZE: usize = 1088;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3Envelope {
    pub magic: [u8; 4],
    pub version: u16,
    pub suite_id: u8,
    pub profile_id: u8,
    pub kdf_id: u8,
    pub salt: [u8; 16],
    pub wrapping_nonce: [u8; 24],
    #[serde(with = "bytes_48")]
    pub encrypted_file_root_key: [u8; 48],
    pub payload_base_nonce: [u8; 24],
    pub plaintext_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3HpkeEnvelope {
    pub magic: [u8; 4],
    pub version: u16,
    pub envelope_revision: u8,
    pub payload_suite_id: u8,
    pub payload_base_nonce: [u8; 24],
    pub plaintext_len: u64,
    #[serde(with = "hpke_recipients")]
    pub recipients: Vec<V3HpkeRecipient>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3HpkeRecipient {
    pub recipient_suite_id: u8,
    pub key_id: [u8; 32],
    pub enc: [u8; 32],
    #[serde(with = "bytes_48")]
    pub encrypted_file_root_key: [u8; 48],
}

#[derive(Serialize)]
pub struct V3HpkePayloadCore<'a> {
    pub magic: &'a [u8; 4],
    pub version: u16,
    pub envelope_revision: u8,
    pub payload_suite_id: u8,
    pub payload_base_nonce: &'a [u8; 24],
    pub plaintext_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3MutableEnvelope {
    pub magic: [u8; 4],
    pub version: u16,
    pub envelope_revision: u8,
    pub payload_suite_id: u8,
    pub payload_base_nonce: [u8; 24],
    pub plaintext_len: u64,
    pub payload_binding: [u8; 32],
    #[serde(with = "mutable_slots")]
    pub slots: Vec<V3MutableSlot>,
    pub header_authenticator: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum V3MutableSlot {
    Password(V3MutablePasswordSlot),
    X25519Hpke(V3MutableX25519HpkeSlot),
    MlKem768(V3MutableMlKem768Slot),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3MutablePasswordSlot {
    pub profile_id: u8,
    pub kdf_id: u8,
    pub salt: [u8; 16],
    pub wrapping_nonce: [u8; 24],
    #[serde(with = "bytes_48")]
    pub encrypted_file_root_key: [u8; 48],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3MutableX25519HpkeSlot {
    pub key_id: [u8; 32],
    pub enc: [u8; 32],
    #[serde(with = "bytes_48")]
    pub encrypted_file_root_key: [u8; 48],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3MutableMlKem768Slot {
    pub key_id: [u8; 32],
    #[serde(with = "boxed_mlkem768_ciphertext")]
    pub encapsulation_ciphertext: Box<[u8; V3_MLKEM768_CIPHERTEXT_SIZE]>,
    pub wrapping_nonce: [u8; 24],
    #[serde(with = "bytes_48")]
    pub encrypted_file_root_key: [u8; 48],
}

#[derive(Serialize)]
pub struct V3MutablePayloadCore<'a> {
    pub magic: &'a [u8; 4],
    pub version: u16,
    pub envelope_revision: u8,
    pub payload_suite_id: u8,
    pub payload_base_nonce: &'a [u8; 24],
    pub plaintext_len: u64,
}

#[derive(Serialize)]
pub struct V3MutableEnvelopeAuth<'a> {
    pub magic: &'a [u8; 4],
    pub version: u16,
    pub envelope_revision: u8,
    pub payload_suite_id: u8,
    pub payload_base_nonce: &'a [u8; 24],
    pub plaintext_len: u64,
    pub payload_binding: &'a [u8; 32],
    pub slots: &'a [V3MutableSlot],
}

mod mutable_slots {
    use super::{V3MutableSlot, V3_MUTABLE_MAX_SLOTS};
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(slots: &[V3MutableSlot], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(slots.len()))?;
        for slot in slots {
            sequence.serialize_element(slot)?;
        }
        sequence.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<V3MutableSlot>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SlotsVisitor;

        impl<'de> Visitor<'de> for SlotsVisitor {
            type Value = Vec<V3MutableSlot>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one to 65 v3 mutable root-wrap slots")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let hinted = sequence.size_hint().unwrap_or(0);
                if hinted > V3_MUTABLE_MAX_SLOTS {
                    return Err(A::Error::invalid_length(hinted, &self));
                }
                let mut slots = Vec::with_capacity(hinted.min(V3_MUTABLE_MAX_SLOTS));
                while let Some(slot) = sequence.next_element()? {
                    if slots.len() == V3_MUTABLE_MAX_SLOTS {
                        return Err(A::Error::invalid_length(slots.len() + 1, &self));
                    }
                    slots.push(slot);
                }
                if slots.is_empty() {
                    return Err(A::Error::invalid_length(0, &self));
                }
                Ok(slots)
            }
        }

        deserializer.deserialize_seq(SlotsVisitor)
    }
}

mod boxed_mlkem768_ciphertext {
    use super::V3_MLKEM768_CIPHERTEXT_SIZE;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(
        bytes: &[u8; V3_MLKEM768_CIPHERTEXT_SIZE],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(V3_MLKEM768_CIPHERTEXT_SIZE)?;
        for byte in bytes.iter() {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Box<[u8; V3_MLKEM768_CIPHERTEXT_SIZE]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CiphertextVisitor;

        impl<'de> Visitor<'de> for CiphertextVisitor {
            type Value = Box<[u8; V3_MLKEM768_CIPHERTEXT_SIZE]>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "exactly {V3_MLKEM768_CIPHERTEXT_SIZE} ML-KEM-768 ciphertext bytes"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|length| length != V3_MLKEM768_CIPHERTEXT_SIZE)
                {
                    return Err(A::Error::invalid_length(
                        sequence.size_hint().unwrap_or(0),
                        &self,
                    ));
                }
                let mut bytes = [0; V3_MLKEM768_CIPHERTEXT_SIZE];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(A::Error::invalid_length(
                        V3_MLKEM768_CIPHERTEXT_SIZE + 1,
                        &self,
                    ));
                }
                Ok(Box::new(bytes))
            }
        }

        deserializer.deserialize_tuple(V3_MLKEM768_CIPHERTEXT_SIZE, CiphertextVisitor)
    }
}

mod hpke_recipients {
    use super::{V3HpkeRecipient, V3_HPKE_MAX_RECIPIENTS};
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(recipients: &[V3HpkeRecipient], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(recipients.len()))?;
        for recipient in recipients {
            sequence.serialize_element(recipient)?;
        }
        sequence.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<V3HpkeRecipient>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RecipientsVisitor;

        impl<'de> Visitor<'de> for RecipientsVisitor {
            type Value = Vec<V3HpkeRecipient>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one to 64 HPKE recipient slots")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let hinted = sequence.size_hint().unwrap_or(0);
                if hinted > V3_HPKE_MAX_RECIPIENTS {
                    return Err(A::Error::invalid_length(hinted, &self));
                }
                let mut recipients = Vec::with_capacity(hinted.min(V3_HPKE_MAX_RECIPIENTS));
                while let Some(recipient) = sequence.next_element()? {
                    if recipients.len() == V3_HPKE_MAX_RECIPIENTS {
                        return Err(A::Error::invalid_length(recipients.len() + 1, &self));
                    }
                    recipients.push(recipient);
                }
                if recipients.is_empty() {
                    return Err(A::Error::invalid_length(0, &self));
                }
                Ok(recipients)
            }
        }

        deserializer.deserialize_seq(RecipientsVisitor)
    }
}

#[derive(Serialize)]
pub struct V3RootWrapAad<'a> {
    pub magic: &'a [u8; 4],
    pub version: u16,
    pub suite_id: u8,
    pub profile_id: u8,
    pub kdf_id: u8,
    pub salt: &'a [u8; 16],
    pub wrapping_nonce: &'a [u8; 24],
    pub payload_base_nonce: &'a [u8; 24],
    pub plaintext_len: u64,
}

mod bytes_48 {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(48)?;
        for byte in bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = [u8; 48];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 48 bytes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0; 48];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(index, &self))?;
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_tuple(48, BytesVisitor)
    }
}

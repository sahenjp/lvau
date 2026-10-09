use crate::crypto::keys::{HybridPublicKey, HybridPublicKeyFormat};
use crate::crypto::CryptoError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_RECIPIENT_GROUP_FILE_SIZE: u64 = 1024 * 1024;

fn read_recipient_group_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("Failed to read recipient group file: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to inspect recipient group file: {e}"))?;
    if !metadata.is_file() || metadata.len() > MAX_RECIPIENT_GROUP_FILE_SIZE {
        return Err("Recipient group file is invalid or too large".into());
    }

    let mut content = String::new();
    file.take(MAX_RECIPIENT_GROUP_FILE_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(|e| format!("Failed to read recipient group file: {e}"))?;
    if content.len() as u64 > MAX_RECIPIENT_GROUP_FILE_SIZE {
        return Err("Recipient group file is invalid or too large".into());
    }
    Ok(content)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientGroup {
    pub name: String,
    pub description: Option<String>,
    pub recipients: Vec<GroupRecipient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupRecipient {
    pub name: String,
    pub key: HybridPublicKeyFormat,
}

impl RecipientGroup {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = read_recipient_group_file(path.as_ref())?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse recipient group: {}", e))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize recipient group: {}", e))?;
        if content.len() as u64 > MAX_RECIPIENT_GROUP_FILE_SIZE {
            return Err("Recipient group file is too large".into());
        }
        fs::write(path, content).map_err(|e| format!("Failed to write recipient group file: {}", e))
    }

    pub fn extract_public_keys(&self) -> Result<Vec<HybridPublicKey>, CryptoError> {
        // Fail fast before per-recipient encapsulation work. Envelopes with
        // more recipients are rejected later by envelope validation, so the
        // failure outcome is unchanged while CPU work is bounded.
        if self.recipients.len() > crate::crypto::MAX_RECIPIENTS {
            return Err(CryptoError::Validation("Too many recipients in group"));
        }
        let mut keys = Vec::new();
        for rec in &self.recipients {
            keys.push(HybridPublicKey::from_format(&rec.key)?);
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_recipient_group_is_rejected_before_saving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group.toml");
        fs::write(&path, "preserve-me").unwrap();
        let group = RecipientGroup {
            name: "x".repeat(MAX_RECIPIENT_GROUP_FILE_SIZE as usize),
            description: None,
            recipients: Vec::new(),
        };

        let error = group.save_to_file(&path).unwrap_err();
        assert!(error.contains("too large"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "preserve-me");
    }

    #[test]
    fn oversized_recipient_group_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.toml");
        fs::write(
            &path,
            vec![b'x'; MAX_RECIPIENT_GROUP_FILE_SIZE as usize + 1],
        )
        .unwrap();

        let error = RecipientGroup::load_from_file(&path).unwrap_err();
        assert!(error.contains("too large"));
    }

    #[test]
    fn recipient_group_beyond_envelope_limit_is_rejected_before_encapsulation() {
        use crate::crypto::keys::HybridPublicKeyFormat;
        let recipients = (0..crate::crypto::MAX_RECIPIENTS + 1)
            .map(|index| GroupRecipient {
                name: format!("member-{index}"),
                key: HybridPublicKeyFormat {
                    x25519_pub: String::new(),
                    mlkem_pub: String::new(),
                },
            })
            .collect();
        let group = RecipientGroup {
            name: "too-many".into(),
            description: None,
            recipients,
        };
        assert!(group.extract_public_keys().is_err());
    }
}

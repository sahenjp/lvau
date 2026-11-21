#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use lvau_core::crypto::{decrypt_memory_keypair, decrypt_memory_password, keys::HybridPrivateKey};
use secrecy::SecretString;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const SFX_TRAILER_SIZE: u64 = 16;
const SFX_MAGIC: &[u8; 8] = b"LVAUSFX1";

fn extract_payload() -> Result<Vec<u8>, String> {
    let exe_path = env::current_exe().map_err(|e| e.to_string())?;
    let mut file = File::open(&exe_path).map_err(|e| e.to_string())?;
    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    extract_payload_from_reader(&mut file, file_len)
}

fn extract_payload_from_reader<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
) -> Result<Vec<u8>, String> {
    let trailer_start = file_len
        .checked_sub(SFX_TRAILER_SIZE)
        .ok_or_else(|| "File too small to be an SFX.".to_string())?;
    reader
        .seek(SeekFrom::Start(trailer_start))
        .map_err(|_| "Failed to seek to trailer.".to_string())?;

    let mut trailer = [0u8; SFX_TRAILER_SIZE as usize];
    reader
        .read_exact(&mut trailer)
        .map_err(|_| "Failed to read trailer.".to_string())?;
    if &trailer[8..16] != SFX_MAGIC {
        return Err("This executable does not contain a valid Lvau SFX payload.".to_string());
    }

    let payload_len = u64::from_le_bytes(
        trailer[0..8]
            .try_into()
            .map_err(|_| "Invalid SFX payload length.".to_string())?,
    );
    let payload_start = trailer_start
        .checked_sub(payload_len)
        .ok_or_else(|| "SFX payload length exceeds the executable size.".to_string())?;
    let payload_len = usize::try_from(payload_len)
        .map_err(|_| "SFX payload is too large for this platform.".to_string())?;

    reader
        .seek(SeekFrom::Start(payload_start))
        .map_err(|_| "Failed to seek to payload.".to_string())?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| "Not enough memory for the SFX payload.".to_string())?;
    payload.resize(payload_len, 0);
    reader
        .read_exact(&mut payload)
        .map_err(|_| "Failed to read payload bytes.".to_string())?;
    Ok(payload)
}

fn write_plaintext_no_clobber(path: &Path, plaintext: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            "Refusing to overwrite the selected output file.".to_string()
        } else {
            format!("Failed to create output file: {error}")
        }
    })?;

    let result = (|| -> std::io::Result<()> {
        file.write_all(plaintext)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Failed to write output file: {error}"));
    }

    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("Failed to sync output directory: {error}"))?;
    }

    Ok(())
}

#[derive(PartialEq)]
enum AuthMode {
    Password,
    KeyFile,
}

struct SfxExtractorApp {
    payload: Option<Vec<u8>>,
    payload_error: Option<String>,
    auth_mode: AuthMode,
    secret: String,
    seed: String,
    keyfile_path: Option<PathBuf>,
    out_file: Option<PathBuf>,
    status: String,
}

impl SfxExtractorApp {
    fn new() -> Self {
        let (payload, payload_error) = match extract_payload() {
            Ok(payload) => (Some(payload), None),
            Err(error) => (None, Some(error)),
        };

        Self {
            payload,
            payload_error,
            auth_mode: AuthMode::Password,
            secret: String::new(),
            seed: String::new(),
            keyfile_path: None,
            out_file: None,
            status: String::new(),
        }
    }

    fn decrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, lvau_core::crypto::CryptoError> {
        match self.auth_mode {
            AuthMode::Password => {
                let password = SecretString::from(std::mem::take(&mut self.secret));
                let seed = std::mem::take(&mut self.seed);
                let seed = if seed.is_empty() {
                    None
                } else {
                    Some(SecretString::from(seed))
                };
                decrypt_memory_password(payload, password, seed)
            }
            AuthMode::KeyFile => {
                // Clear any password material left in the UI before switching modes.
                drop(SecretString::from(std::mem::take(&mut self.secret)));
                drop(SecretString::from(std::mem::take(&mut self.seed)));
                let key_path = self
                    .keyfile_path
                    .as_ref()
                    .ok_or(lvau_core::crypto::CryptoError::DecryptionFailed)?;
                let private_key = HybridPrivateKey::load_from_file(key_path)
                    .map_err(|_| lvau_core::crypto::CryptoError::DecryptionFailed)?;
                decrypt_memory_keypair(payload, &private_key)
            }
        }
    }
}

impl eframe::App for SfxExtractorApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Lvau SFX Extractor");
            ui.add_space(20.0);

            if let Some(error) = &self.payload_error {
                ui.label(egui::RichText::new(format!("Error: {error}")).color(egui::Color32::RED));
                return;
            }

            ui.horizontal(|ui| {
                ui.radio_value(&mut self.auth_mode, AuthMode::Password, "Use Password");
                ui.radio_value(&mut self.auth_mode, AuthMode::KeyFile, "Use Key File");
            });
            ui.add_space(10.0);

            if self.auth_mode == AuthMode::Password {
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.secret).password(true));
                });
                ui.horizontal(|ui| {
                    ui.label("Seed (Pepper, Optional):");
                    ui.add(egui::TextEdit::singleline(&mut self.seed).password(true));
                });
            } else {
                ui.horizontal(|ui| {
                    if ui.button("Select Private Key (.lvau-key)").clicked() {
                        let dialog =
                            rfd::FileDialog::new().add_filter("Private Key", &["lvau-key"]);
                        if let Some(path) = dialog.pick_file() {
                            self.keyfile_path = Some(path);
                        }
                    }
                    if let Some(path) = &self.keyfile_path {
                        ui.label(path.display().to_string());
                    }
                });
            }

            ui.add_space(20.0);
            ui.horizontal(|ui| {
                if ui.button("Select Output File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().save_file() {
                        self.out_file = Some(path);
                    }
                }
                if let Some(path) = &self.out_file {
                    ui.label(path.display().to_string());
                }
            });
            ui.add_space(20.0);

            let can_proceed = self.out_file.is_some()
                && ((self.auth_mode == AuthMode::Password && !self.secret.is_empty())
                    || (self.auth_mode == AuthMode::KeyFile && self.keyfile_path.is_some()));

            if ui
                .add_enabled(can_proceed, egui::Button::new("Decrypt & Extract"))
                .clicked()
            {
                if let Some(out_file) = self.out_file.clone() {
                    if let Some(payload) = self.payload.take() {
                        let decrypt_result = self.decrypt(&payload);
                        self.payload = Some(payload);
                        match decrypt_result {
                            Ok(mut plaintext) => {
                                let write_result =
                                    write_plaintext_no_clobber(&out_file, &plaintext);
                                plaintext.fill(0);
                                self.status = match write_result {
                                    Ok(()) => "Extraction Successful!".to_string(),
                                    Err(error) => error,
                                };
                            }
                            Err(_) => {
                                self.status =
                                    "Decryption Failed! Wrong password or corrupted file."
                                        .to_string();
                            }
                        }
                    }
                }
            }

            ui.add_space(20.0);
            if !self.status.is_empty() {
                let color = if self.status.contains("Successful") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::RED
                };
                ui.label(egui::RichText::new(&self.status).color(color));
            }
        });
    }
}

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([500.0, 350.0]),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Lvau SFX Extractor",
        options,
        Box::new(|_cc| Ok(Box::new(SfxExtractorApp::new()))),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn trailer_length_cannot_seek_before_start() {
        let mut bytes = vec![0u8; 32];
        bytes.extend_from_slice(&1_000u64.to_le_bytes());
        bytes.extend_from_slice(SFX_MAGIC);
        let len = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        assert!(extract_payload_from_reader(&mut cursor, len).is_err());
    }

    #[test]
    fn valid_payload_is_read_exactly() {
        let payload = b"encrypted-capsule";
        let mut bytes = payload.to_vec();
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(SFX_MAGIC);
        let len = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        assert_eq!(
            extract_payload_from_reader(&mut cursor, len).unwrap(),
            payload
        );
    }

    #[test]
    fn output_writer_refuses_existing_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("lvau-sfx-test-{}-{unique}", std::process::id()));
        fs::write(&path, b"existing").unwrap();

        let result = write_plaintext_no_clobber(&path, b"replacement");
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"existing");
        fs::remove_file(path).unwrap();
    }
}

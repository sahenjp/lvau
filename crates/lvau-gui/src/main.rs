#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use log::{LevelFilter, Log, Metadata, Record};
use lvau_core::crypto::{
    decrypt_file_keypair_with_overwrite, decrypt_file_password_with_overwrite,
    encrypt_file_keypairs_with_overwrite, encrypt_file_password_with_overwrite,
    keys::{generate_keypair, HybridPrivateKey, HybridPublicKey},
};
use lvau_core::preflight::run_preflight;
use lvau_protocol::envelope::SecurityProfile;
use secrecy::SecretString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    mpsc::{self, Receiver, TryRecvError},
    Arc, Mutex,
};
use std::time::Duration;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

const MAX_GUI_LOG_BYTES: usize = 64 * 1024;

struct GuiLogger {
    logs: Arc<Mutex<String>>,
}

impl Log for GuiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Ok(mut logs) = self.logs.lock() {
            logs.push_str(&format!("[{}] {}\n", record.level(), record.args()));
            if logs.len() > MAX_GUI_LOG_BYTES {
                let mut remove = logs.len() - MAX_GUI_LOG_BYTES;
                while !logs.is_char_boundary(remove) {
                    remove += 1;
                }
                logs.drain(..remove);
            }
        }
    }

    fn flush(&self) {}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Password,
    KeyFile,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OperationMode {
    Encrypt,
    Decrypt,
    Inspect,
}

enum Credential {
    Password { password: String, seed: String },
    KeyFile(PathBuf),
}

enum GuiTask {
    Inspect {
        in_file: PathBuf,
    },
    Crypto {
        mode: OperationMode,
        credential: Credential,
        in_file: PathBuf,
        out_file: PathBuf,
        profile: SecurityProfile,
        sfx: bool,
        force: bool,
    },
}

enum GuiMessage {
    Progress(u64),
    Finished(Result<String, String>),
}

struct LvauGuiApp {
    mode: OperationMode,
    auth_mode: AuthMode,
    in_file: Option<PathBuf>,
    secret: String,
    secret_confirmation: String,
    seed: String,
    show_secrets: bool,
    keyfile_path: Option<PathBuf>,
    status: String,
    profile: SecurityProfile,
    sfx: bool,
    force_overwrite: bool,
    logs: Arc<Mutex<String>>,
    worker: Option<Receiver<GuiMessage>>,
    busy: bool,
    processed_bytes: u64,
}

impl LvauGuiApp {
    fn new(logs: Arc<Mutex<String>>) -> Self {
        Self {
            mode: OperationMode::Encrypt,
            auth_mode: AuthMode::Password,
            in_file: None,
            secret: String::new(),
            secret_confirmation: String::new(),
            seed: String::new(),
            show_secrets: false,
            keyfile_path: None,
            status: String::new(),
            profile: SecurityProfile::Balanced,
            sfx: false,
            force_overwrite: false,
            logs,
            worker: None,
            busy: false,
            processed_bytes: 0,
        }
    }

    fn start_task(&mut self, task: GuiTask) {
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.busy = true;
        self.processed_bytes = 0;
        self.status = "Processing...".into();

        std::thread::spawn(move || {
            let result = run_task(task, &sender);
            let _ = sender.send(GuiMessage::Finished(result));
        });
    }

    fn poll_worker(&mut self) {
        let Some(receiver) = self.worker.as_ref() else {
            return;
        };
        let mut finished = None;
        loop {
            match receiver.try_recv() {
                Ok(GuiMessage::Progress(bytes)) => self.processed_bytes = bytes,
                Ok(GuiMessage::Finished(result)) => {
                    finished = Some(result);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    finished = Some(Err("Background operation ended unexpectedly".into()));
                    break;
                }
            }
        }

        if let Some(result) = finished {
            self.busy = false;
            self.worker = None;
            self.status = match result {
                Ok(message) => format!("Success: {message}"),
                Err(error) => format!("Error: {error}"),
            };
        }
    }

    fn clear_sensitive_fields(&mut self) {
        self.secret.zeroize();
        self.secret_confirmation.zeroize();
        self.seed.zeroize();
    }

    fn validation_error(&self) -> Option<&'static str> {
        if self.in_file.is_none() {
            return Some("Select an input file");
        }
        if self.mode == OperationMode::Inspect {
            return None;
        }
        match self.auth_mode {
            AuthMode::Password => {
                validate_password_fields(self.mode, &self.secret, &self.secret_confirmation).err()
            }
            AuthMode::KeyFile if self.keyfile_path.is_none() => {
                Some("Select the required key file")
            }
            AuthMode::KeyFile => None,
        }
    }

    fn selected_credential(&self) -> Option<Credential> {
        match self.auth_mode {
            AuthMode::Password if !self.secret.is_empty() => Some(Credential::Password {
                password: self.secret.clone(),
                seed: self.seed.clone(),
            }),
            AuthMode::KeyFile => self.keyfile_path.clone().map(Credential::KeyFile),
            AuthMode::Password => None,
        }
    }

    fn begin_selected_operation(&mut self) {
        if let Some(error) = self.validation_error() {
            self.status = format!("Error: {error}");
            return;
        }

        let Some(in_file) = self.in_file.clone() else {
            self.status = "Error: Select an input file".into();
            return;
        };

        if self.mode == OperationMode::Inspect {
            self.start_task(GuiTask::Inspect { in_file });
            return;
        }

        let mut dialog = rfd::FileDialog::new()
            .set_file_name(suggested_output_name(&in_file, self.mode, self.sfx));
        if let Some(parent) = in_file.parent() {
            dialog = dialog.set_directory(parent);
        }
        if self.mode == OperationMode::Encrypt {
            dialog = if self.sfx {
                dialog.add_filter("Executable", &["exe"])
            } else {
                dialog.add_filter("Lvau", &["lvau"])
            };
        }
        let Some(out_file) = dialog.save_file() else {
            return;
        };
        if out_file == in_file {
            self.status = "Error: Input and output paths must be different.".into();
            return;
        }
        if out_file.exists() && !self.force_overwrite {
            self.status =
                "Error: Output exists. Enable Force Overwrite or choose another path.".into();
            return;
        }
        let Some(credential) = self.selected_credential() else {
            self.status = "Error: Enter a password or select the required key file".into();
            return;
        };

        let task = GuiTask::Crypto {
            mode: self.mode,
            credential,
            in_file,
            out_file,
            profile: self.profile.clone(),
            sfx: self.sfx,
            force: self.force_overwrite,
        };
        self.clear_sensitive_fields();
        self.start_task(task);
    }
}

fn validate_password_fields(
    mode: OperationMode,
    password: &str,
    confirmation: &str,
) -> Result<(), &'static str> {
    if password.is_empty() {
        return Err("Enter a password");
    }
    if mode == OperationMode::Encrypt {
        if confirmation.is_empty() {
            return Err("Confirm the password");
        }
        if password != confirmation {
            return Err("Password confirmation does not match");
        }
    }
    Ok(())
}

fn suggested_output_name(input: &Path, mode: OperationMode, sfx: bool) -> String {
    let file_name = input
        .file_name()
        .map(|name| name.to_string_lossy())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "output".into());

    match mode {
        OperationMode::Encrypt if sfx => format!("{file_name}.exe"),
        OperationMode::Encrypt => format!("{file_name}.lvau"),
        OperationMode::Decrypt => file_name
            .strip_suffix(".lvau")
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{file_name}.decrypted")),
        OperationMode::Inspect => file_name.into_owned(),
    }
}

fn run_task(task: GuiTask, sender: &mpsc::Sender<GuiMessage>) -> Result<String, String> {
    match task {
        GuiTask::Inspect { in_file } => inspect_file(&in_file),
        GuiTask::Crypto {
            mode,
            credential,
            in_file,
            out_file,
            profile,
            sfx,
            force,
        } => run_crypto(
            mode, credential, &in_file, &out_file, profile, sfx, force, sender,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_crypto(
    mode: OperationMode,
    credential: Credential,
    in_file: &Path,
    out_file: &Path,
    profile: SecurityProfile,
    sfx: bool,
    force: bool,
    sender: &mpsc::Sender<GuiMessage>,
) -> Result<String, String> {
    if in_file == out_file {
        return Err("Input and output paths must be different".into());
    }
    if out_file.exists() && !force {
        return Err(format!("Output already exists: {}", out_file.display()));
    }
    if sfx && mode != OperationMode::Encrypt {
        return Err("SFX is available only for encryption".into());
    }

    let temp_dir = if sfx {
        Some(tempfile::tempdir().map_err(|error| error.to_string())?)
    } else {
        None
    };
    let crypto_output = temp_dir
        .as_ref()
        .map(|dir| dir.path().join("payload.lvau"))
        .unwrap_or_else(|| out_file.to_path_buf());

    let mut progress = |bytes| {
        let _ = sender.send(GuiMessage::Progress(bytes));
    };
    let result = match credential {
        Credential::Password { password, seed } => {
            let password = SecretString::from(password);
            let seed = if seed.is_empty() {
                None
            } else {
                Some(SecretString::from(seed))
            };
            if mode == OperationMode::Encrypt {
                encrypt_file_password_with_overwrite(
                    in_file,
                    &crypto_output,
                    password,
                    seed,
                    profile,
                    Some(&mut progress),
                    None,
                    false,
                    force,
                )
            } else {
                decrypt_file_password_with_overwrite(
                    in_file,
                    &crypto_output,
                    password,
                    seed,
                    Some(&mut progress),
                    force,
                )
            }
        }
        Credential::KeyFile(key_path) => {
            if mode == OperationMode::Encrypt {
                let public_key = HybridPublicKey::load_from_file(&key_path)
                    .map_err(|error| format!("Could not load public key: {error}"))?;
                encrypt_file_keypairs_with_overwrite(
                    in_file,
                    &crypto_output,
                    &[public_key],
                    profile,
                    Some(&mut progress),
                    None,
                    false,
                    force,
                )
            } else {
                let private_key = HybridPrivateKey::load_from_file(&key_path)
                    .map_err(|error| format!("Could not load private key: {error}"))?;
                decrypt_file_keypair_with_overwrite(
                    in_file,
                    &crypto_output,
                    &private_key,
                    Some(&mut progress),
                    force,
                )
            }
        }
    };
    result.map_err(|error| error.to_string())?;

    if sfx {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let executable_dir = executable
            .parent()
            .ok_or_else(|| "Could not determine the GUI executable directory".to_string())?;
        let stub_path = executable_dir.join("lvau-stub.exe");
        if !stub_path.is_file() {
            return Err(format!(
                "lvau-stub.exe was not found in {}",
                executable_dir.display()
            ));
        }
        build_sfx_file(&stub_path, &crypto_output, out_file, force)
            .map_err(|error| format!("Could not build SFX: {error}"))?;
    }

    Ok(format!("Output saved to {}", out_file.display()))
}

fn inspect_file(in_file: &Path) -> Result<String, String> {
    let verify_path = in_file.with_extension("lvau-verify");
    let verify_key = if verify_path.is_file() {
        lvau_core::signing::load_verify_key(&verify_path).ok()
    } else {
        None
    };
    let policy_path = Path::new(".lvau-policy.toml");
    let policy = if policy_path.is_file() {
        lvau_core::policy::CapsulePolicy::load_from_file(policy_path).ok()
    } else {
        None
    };
    let result = run_preflight(in_file, verify_key.as_ref(), policy.as_ref());
    if !result.parse_ok {
        return Err(result
            .parse_error
            .unwrap_or_else(|| "Envelope parsing failed".into()));
    }

    let mut details = format!(
        "Preflight: {:?}\nVersion: {}\nProfile: {}\nAlgorithm: {}\nContent type: {}\nRecipients: {}\n",
        result.status,
        result.version,
        result.profile,
        result.algorithm,
        result.content_type,
        result.recipient_count
    );
    if result.signature_present {
        match result.signature_valid {
            Some(true) => details.push_str(
                "Signature: cryptographically valid with the adjacent verify key (identity is not trusted automatically)\n",
            ),
            Some(false) => details.push_str("Signature: INVALID for the adjacent verify key\n"),
            None => details.push_str("Signature: present but unverified\n"),
        }
    } else {
        details.push_str("Signature: absent\n");
    }
    if let Some(policy_ok) = result.policy_ok {
        details.push_str(&format!(
            "Local policy: {}\n",
            if policy_ok { "PASS" } else { "FAIL" }
        ));
    }
    for warning in result.warnings.into_iter().chain(result.policy_warnings) {
        details.push_str(&format!("Warning: {warning}\n"));
    }
    for error in result.errors.into_iter().chain(result.policy_violations) {
        details.push_str(&format!("Error: {error}\n"));
    }
    Ok(details)
}

fn build_sfx_file(
    stub_path: &Path,
    payload_path: &Path,
    output_path: &Path,
    force: bool,
) -> io::Result<()> {
    if output_path.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("output already exists: {}", output_path.display()),
        ));
    }
    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let payload_len = fs::metadata(payload_path)?.len();
    let mut temp = NamedTempFile::new_in(parent)?;
    let mut stub = File::open(stub_path)?;
    let mut payload = File::open(payload_path)?;
    io::copy(&mut stub, &mut temp)?;
    let copied = io::copy(&mut payload, &mut temp)?;
    if copied != payload_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "SFX payload changed while it was copied",
        ));
    }
    temp.write_all(&payload_len.to_le_bytes())?;
    temp.write_all(b"LVAUSFX1")?;
    temp.as_file().sync_all()?;

    lvau_core::crypto::output::persist_temp_path(temp.into_temp_path(), output_path, force)?;
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

impl eframe::App for LvauGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading(format!("Lvau {} - Local File Encryption", env!("CARGO_PKG_VERSION")));
                ui.label(
                    egui::RichText::new(
                        "Experimental software; no formal independent security audit has been completed.",
                    )
                    .color(egui::Color32::YELLOW),
                );
                ui.add_space(14.0);

                ui.add_enabled_ui(!self.busy, |ui| {
                    if ui.button("Generate Experimental Hybrid Keypair...").clicked() {
                        let dialog = rfd::FileDialog::new()
                            .set_title("Save Private Key")
                            .add_filter("Lvau Key", &["lvau-key"]);
                        if let Some(private_path) = dialog.save_file() {
                            let public_path = private_path.with_extension("lvau-pub");
                            let (private_key, public_key) = generate_keypair();
                            self.status = match private_key.save_to_file(&private_path) {
                                Ok(()) => match public_key.save_to_file(&public_path) {
                                    Ok(()) => format!(
                                        "Success: Experimental identity generated\nPrivate: {}\nPublic: {}",
                                        private_path.display(),
                                        public_path.display()
                                    ),
                                    Err(error) => format!("Error: Could not save public key: {error}"),
                                },
                                Err(error) => format!("Error: Could not save private key: {error}"),
                            };
                        }
                    }

                    ui.add_space(14.0);
                    let previous_mode = self.mode;
                    ui.horizontal_wrapped(|ui| {
                        ui.radio_value(&mut self.mode, OperationMode::Encrypt, "Encrypt");
                        ui.radio_value(&mut self.mode, OperationMode::Decrypt, "Decrypt");
                        ui.radio_value(&mut self.mode, OperationMode::Inspect, "Inspect");
                    });
                    if self.mode != previous_mode {
                        self.keyfile_path = None;
                        self.secret_confirmation.zeroize();
                        self.status.clear();
                        if self.mode != OperationMode::Encrypt {
                            self.sfx = false;
                        }
                    }

                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Select Target File").clicked() {
                            let mut dialog = rfd::FileDialog::new();
                            if matches!(self.mode, OperationMode::Decrypt | OperationMode::Inspect) {
                                dialog = dialog.add_filter("Lvau Encrypted", &["lvau"]);
                            }
                            if let Some(path) = dialog.pick_file() {
                                self.in_file = Some(path);
                                self.status.clear();
                            }
                        }
                        if self.in_file.is_some() && ui.button("Clear").clicked() {
                            self.in_file = None;
                            self.status.clear();
                        }
                    });
                    if let Some(path) = &self.in_file {
                        ui.label(egui::RichText::new(path.display().to_string()).monospace());
                        if let Ok(metadata) = fs::metadata(path) {
                            ui.label(format!("Input size: {}", format_bytes(metadata.len())));
                        }
                    }

                    if self.mode != OperationMode::Inspect {
                        ui.horizontal_wrapped(|ui| {
                            ui.radio_value(&mut self.auth_mode, AuthMode::Password, "Use Password");
                            ui.radio_value(&mut self.auth_mode, AuthMode::KeyFile, "Use Experimental Hybrid Key File");
                        });
                        if self.auth_mode == AuthMode::Password {
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Password:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.secret)
                                        .password(!self.show_secrets),
                                );
                            });
                            if self.mode == OperationMode::Encrypt {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label("Confirm password:");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.secret_confirmation)
                                            .password(!self.show_secrets),
                                    );
                                });
                            }
                            ui.horizontal_wrapped(|ui| {
                                ui.label("Seed (optional pepper):");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.seed)
                                        .password(!self.show_secrets),
                                );
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.checkbox(&mut self.show_secrets, "Show sensitive fields");
                                if ui.button("Clear sensitive fields").clicked() {
                                    self.clear_sensitive_fields();
                                }
                            });
                        } else {
                            ui.label(
                                egui::RichText::new("Hybrid X25519 + ML-KEM-768 recipients are experimental and unaudited.")
                                    .color(egui::Color32::YELLOW),
                            );
                            ui.horizontal_wrapped(|ui| {
                                let label = if self.mode == OperationMode::Encrypt {
                                    "Select Public Key (.lvau-pub)"
                                } else {
                                    "Select Private Key (.lvau-key)"
                                };
                                if ui.button(label).clicked() {
                                    let filter = if self.mode == OperationMode::Encrypt {
                                        ("Public Key", "lvau-pub")
                                    } else {
                                        ("Private Key", "lvau-key")
                                    };
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter(filter.0, &[filter.1])
                                        .pick_file()
                                    {
                                        self.keyfile_path = Some(path);
                                    }
                                }
                                if let Some(path) = &self.keyfile_path {
                                    ui.label(path.display().to_string());
                                }
                            });
                        }
                    }

                    if self.mode == OperationMode::Encrypt {
                        ui.add_space(8.0);
                        ui.label("Security profile:");
                        ui.horizontal_wrapped(|ui| {
                            ui.radio_value(&mut self.profile, SecurityProfile::Fast, "Fast");
                            ui.radio_value(&mut self.profile, SecurityProfile::Balanced, "Balanced");
                            ui.radio_value(&mut self.profile, SecurityProfile::Archive, "Archive");
                            ui.radio_value(&mut self.profile, SecurityProfile::Paranoid, "Paranoid (experimental)");
                            ui.radio_value(&mut self.profile, SecurityProfile::Extreme, "Extreme (experimental)");
                        });
                        if matches!(self.profile, SecurityProfile::Paranoid | SecurityProfile::Extreme) {
                            ui.label(
                                egui::RichText::new("Cascade/LCO profiles are experimental; more layers are not an audit result.")
                                    .color(egui::Color32::YELLOW),
                            );
                        }
                        ui.checkbox(&mut self.sfx, "Create Self-Extracting Archive (SFX .exe)");
                        if self.sfx {
                            ui.label(
                                egui::RichText::new("SFX is experimental and requires lvau-stub.exe beside the GUI.")
                                    .color(egui::Color32::YELLOW),
                            );
                        }
                    }

                    if self.mode != OperationMode::Inspect {
                        ui.checkbox(&mut self.force_overwrite, "Force Overwrite");
                    }

                    let validation_error = self.validation_error();
                    let action = match self.mode {
                        OperationMode::Encrypt => "Encrypt & Save",
                        OperationMode::Decrypt => "Decrypt & Save",
                        OperationMode::Inspect => "Inspect Envelope",
                    };
                    if ui
                        .add_enabled(validation_error.is_none(), egui::Button::new(action))
                        .clicked()
                    {
                        self.begin_selected_operation();
                    }
                    if let Some(error) = validation_error {
                        ui.label(egui::RichText::new(error).weak());
                    }
                });

                if self.busy {
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!("Processed {}", format_bytes(self.processed_bytes)));
                    });
                    if self.mode == OperationMode::Encrypt {
                        if let Some(total) = self
                            .in_file
                            .as_ref()
                            .and_then(|path| fs::metadata(path).ok())
                            .map(|metadata| metadata.len())
                            .filter(|total| *total > 0)
                        {
                            let progress =
                                (self.processed_bytes as f32 / total as f32).clamp(0.0, 1.0);
                            ui.add(
                                egui::ProgressBar::new(progress)
                                    .text(format!("{} total", format_bytes(total))),
                            );
                        }
                    }
                    ui.label("The UI remains responsive. Safe cancellation is not available in this build; wait for completion before closing the app.");
                }

                if !self.status.is_empty() {
                    let color = if self.status.starts_with("Error") {
                        egui::Color32::RED
                    } else if self.status.starts_with("Success") {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::LIGHT_BLUE
                    };
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new(&self.status).color(color));
                }

                ui.add_space(16.0);
                ui.separator();
                egui::CollapsingHeader::new("Diagnostic Logs")
                    .default_open(false)
                    .show(ui, |ui| {
                        if ui.button("Clear").clicked() {
                            if let Ok(mut logs) = self.logs.lock() {
                                logs.clear();
                            }
                        }
                        egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .max_height(150.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                if let Ok(logs) = self.logs.lock() {
                                    if logs.is_empty() {
                                        ui.label(egui::RichText::new("No diagnostic entries.").weak());
                                    } else {
                                        ui.label(egui::RichText::new(logs.as_str()).monospace());
                                    }
                                } else {
                                    ui.label("Log buffer unavailable");
                                }
                            });
                    });
            });
        });
    }
}

fn main() {
    let logs = Arc::new(Mutex::new(String::new()));
    let logger = GuiLogger { logs: logs.clone() };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(LevelFilter::Debug);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 760.0])
            .with_min_inner_size([480.0, 560.0]),
        ..Default::default()
    };

    if let Err(error) = eframe::run_native(
        "Lvau Cryptography",
        options,
        Box::new(|_cc| Ok(Box::new(LvauGuiApp::new(logs)))),
    ) {
        eprintln!("Lvau GUI failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn encryption_requires_matching_password_confirmation() {
        assert_eq!(
            validate_password_fields(OperationMode::Encrypt, "secret", "different"),
            Err("Password confirmation does not match")
        );
        assert_eq!(
            validate_password_fields(OperationMode::Encrypt, "secret", "secret"),
            Ok(())
        );
        assert_eq!(
            validate_password_fields(OperationMode::Decrypt, "secret", ""),
            Ok(())
        );
    }

    #[test]
    fn suggested_output_names_are_conservative() {
        assert_eq!(
            suggested_output_name(Path::new("report.txt"), OperationMode::Encrypt, false),
            "report.txt.lvau"
        );
        assert_eq!(
            suggested_output_name(Path::new("report.txt.lvau"), OperationMode::Decrypt, false),
            "report.txt"
        );
        assert_eq!(
            suggested_output_name(Path::new("report.bin"), OperationMode::Decrypt, false),
            "report.bin.decrypted"
        );
    }

    #[test]
    fn sfx_builder_streams_payload_and_writes_footer() {
        let dir = tempdir().unwrap();
        let stub = dir.path().join("stub.exe");
        let payload = dir.path().join("payload.lvau");
        let output = dir.path().join("output.exe");
        fs::write(&stub, b"stub").unwrap();
        fs::write(&payload, b"encrypted payload").unwrap();

        build_sfx_file(&stub, &payload, &output, false).unwrap();

        let bytes = fs::read(output).unwrap();
        assert!(bytes.starts_with(b"stubencrypted payload"));
        assert_eq!(&bytes[bytes.len() - 8..], b"LVAUSFX1");
        assert_eq!(
            u64::from_le_bytes(bytes[bytes.len() - 16..bytes.len() - 8].try_into().unwrap()),
            b"encrypted payload".len() as u64
        );
    }
}

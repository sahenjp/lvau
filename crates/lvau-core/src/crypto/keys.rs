use base64::Engine;
use kem::Kem as KemTrait;
use kem::KeyExport;
use ml_kem::{DecapsulationKey768, EncapsulationKey768, MlKem768};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::crypto::CryptoError;

type Kem = MlKem768;
const MAX_KEY_FILE_SIZE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub struct HybridPublicKeyFormat {
    pub x25519_pub: String,
    pub mlkem_pub: String,
}

#[derive(Serialize, Deserialize)]
pub struct HybridPrivateKeyFormat {
    pub x25519_priv: String,
    pub mlkem_priv: String,
}

impl std::fmt::Debug for HybridPrivateKeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridPrivateKeyFormat")
            .field("x25519_priv", &"<redacted>")
            .field("mlkem_priv", &"<redacted>")
            .finish()
    }
}

pub struct HybridPublicKey {
    pub x25519: X25519PublicKey,
    pub mlkem: EncapsulationKey768,
}

pub struct HybridPrivateKey {
    pub x25519: StaticSecret,
    pub mlkem: DecapsulationKey768,
}

#[cfg(windows)]
struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
pub(crate) fn set_windows_acl(path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::{
        Authorization::SetEntriesInAclW, Authorization::SetNamedSecurityInfoW,
        Authorization::EXPLICIT_ACCESS_W, Authorization::SET_ACCESS, Authorization::SE_FILE_OBJECT,
        Authorization::TRUSTEE_IS_SID, Authorization::TRUSTEE_IS_USER, GetTokenInformation,
        TokenUser, DACL_SECURITY_INFORMATION, NO_INHERITANCE, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut raw_token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = OwnedHandle(raw_token);

        let mut ret_len = 0;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut ret_len);
        if ret_len == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut token_user_buf = vec![0u8; ret_len as usize];
        if GetTokenInformation(
            token.0,
            TokenUser,
            token_user_buf.as_mut_ptr() as *mut core::ffi::c_void,
            ret_len,
            &mut ret_len,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        let token_user =
            &*(token_user_buf.as_ptr() as *const windows_sys::Win32::Security::TOKEN_USER);
        let user_sid = token_user.User.Sid;

        let mut ea = std::mem::zeroed::<EXPLICIT_ACCESS_W>();
        ea.grfAccessPermissions = FILE_ALL_ACCESS;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = user_sid as *mut u16;

        let mut new_dacl = null_mut();
        let acl_status = SetEntriesInAclW(1, &ea, null_mut(), &mut new_dacl);
        if acl_status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(acl_status as i32));
        }

        let mut path_w: Vec<u16> = path.as_os_str().encode_wide().collect();
        path_w.push(0);

        let status = SetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new_dacl,
            null_mut(),
        );
        LocalFree(new_dacl as _);

        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

fn read_key_file(path: &Path) -> Result<String, CryptoError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_KEY_FILE_SIZE {
        return Err(CryptoError::Validation("Key file is invalid or too large"));
    }

    let mut json = String::new();
    file.take(MAX_KEY_FILE_SIZE + 1).read_to_string(&mut json)?;
    if json.len() as u64 > MAX_KEY_FILE_SIZE {
        return Err(CryptoError::Validation("Key file is invalid or too large"));
    }
    Ok(json)
}

fn write_key_file<P: AsRef<Path>>(
    path: P,
    contents: &str,
    private: bool,
) -> Result<(), CryptoError> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode))?;
    }

    #[cfg(windows)]
    if private {
        set_windows_acl(temp.path())?;
    }

    temp.write_all(contents.as_bytes())?;
    temp.as_file().sync_all()?;

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    temp.persist(path)
        .map_err(|error| CryptoError::Io(error.error))?;

    #[cfg(unix)]
    File::open(parent)?.sync_all()?;

    Ok(())
}

pub fn generate_keypair() -> (HybridPrivateKey, HybridPublicKey) {
    let x25519_priv = StaticSecret::random();
    let x25519_pub = X25519PublicKey::from(&x25519_priv);

    let (mlkem_priv, mlkem_pub) = Kem::generate_keypair();

    let priv_key = HybridPrivateKey {
        x25519: x25519_priv,
        mlkem: mlkem_priv,
    };

    let pub_key = HybridPublicKey {
        x25519: x25519_pub,
        mlkem: mlkem_pub,
    };

    (priv_key, pub_key)
}

impl HybridPublicKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(self.x25519.as_bytes());
        let mlkem_b64 =
            base64::engine::general_purpose::STANDARD.encode(self.mlkem.to_bytes().as_slice());

        let format = HybridPublicKeyFormat {
            x25519_pub: x25519_b64,
            mlkem_pub: mlkem_b64,
        };
        let json =
            serde_json::to_string_pretty(&format).map_err(|_| CryptoError::DecryptionFailed)?;
        write_key_file(path, &json, false)
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let json = read_key_file(path.as_ref())?;
        let format: HybridPublicKeyFormat =
            serde_json::from_str(&json).map_err(|_| CryptoError::DecryptionFailed)?;
        Self::from_format(&format)
    }

    pub fn from_format(format: &HybridPublicKeyFormat) -> Result<Self, CryptoError> {
        let x25519_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.x25519_pub)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.mlkem_pub)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if x25519_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&x25519_bytes);
        let x25519 = X25519PublicKey::from(x_arr);

        let enc_arr: [u8; 1184] = mlkem_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem =
            EncapsulationKey768::new(&enc_arr.into()).map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(Self { x25519, mlkem })
    }
}

impl HybridPrivateKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(self.x25519.to_bytes());
        let mlkem_b64 =
            base64::engine::general_purpose::STANDARD.encode(self.mlkem.to_bytes().as_slice());

        let format = HybridPrivateKeyFormat {
            x25519_priv: x25519_b64,
            mlkem_priv: mlkem_b64,
        };
        let json =
            serde_json::to_string_pretty(&format).map_err(|_| CryptoError::DecryptionFailed)?;
        write_key_file(path, &json, true)
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        // Warn (without failing) when a private key file is group/world
        // accessible. Existing permissive files keep loading so this stays
        // non-breaking; new files are written owner-only by save_to_file.
        #[cfg(unix)]
        if let Ok(metadata) = fs::metadata(path.as_ref()) {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                log::warn!(
                    "Private key file permissions are too broad: {} (use chmod 600)",
                    path.as_ref().display()
                );
            }
        }
        let json = read_key_file(path.as_ref())?;
        let format: HybridPrivateKeyFormat =
            serde_json::from_str(&json).map_err(|_| CryptoError::DecryptionFailed)?;

        let x25519_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.x25519_priv)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_bytes = base64::engine::general_purpose::STANDARD
            .decode(&format.mlkem_priv)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if x25519_bytes.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }

        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&x25519_bytes);
        let x25519 = StaticSecret::from(x_arr);

        let seed_arr: [u8; 64] = mlkem_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem = DecapsulationKey768::from_seed(seed_arr.into());

        Ok(Self { x25519, mlkem })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_key_file_is_rejected_before_json_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.key");
        fs::write(&path, vec![b'x'; MAX_KEY_FILE_SIZE as usize + 1]).unwrap();

        assert!(matches!(
            HybridPrivateKey::load_from_file(&path),
            Err(CryptoError::Validation("Key file is invalid or too large"))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn overwriting_private_key_repairs_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.lvau-key");
        fs::write(&path, "old key").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let (private_key, _) = generate_keypair();

        private_key.save_to_file(&path).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
use std::fs::File;
use std::io;
use std::path::Path;

/// Persist a same-directory temporary path, refusing replacement unless requested.
/// Explicit replacement is atomic; no-clobber never overwrites and may use a hard-link fallback.
pub fn persist_temp_path(
    temp: tempfile::TempPath,
    target: &Path,
    replace_existing: bool,
) -> io::Result<()> {
    if replace_existing {
        temp.persist(target).map_err(io::Error::from)?;
    } else {
        temp.persist_noclobber(target).map_err(io::Error::from)?;
    }

    #[cfg(unix)]
    {
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }

    Ok(())
}

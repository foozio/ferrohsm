use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub fn ensure_secure_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

pub fn open_secure(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let file = options.open(path)?;
    apply_file_permissions(&file)?;
    Ok(file)
}

pub fn ensure_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn apply_file_permissions(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
    }
    let _ = file; // suppress unused on non-unix
    Ok(())
}

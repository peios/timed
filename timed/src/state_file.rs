//! Replacement of daemon state without reusing another writer's staging file.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
const CREATE_ATTEMPTS: usize = 64;

struct Temporary {
    path: PathBuf,
    published: bool,
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Write and sync an exclusively owned temporary file, then rename it over state.
/// The parent directory must be writable only by the daemon and administrators.
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_with(path, bytes, || {
        let serial = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        format!(".timed-{}-{serial}.tmp", std::process::id())
    })
}

fn replace_with(path: &Path, bytes: &[u8], mut name: impl FnMut() -> String) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("state path has no parent"))?;
    for _ in 0..CREATE_ATTEMPTS {
        let temporary = parent.join(name());
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let mut temporary = Temporary {
            path: temporary,
            published: false,
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary.path, path)?;
        temporary.published = true;
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "state staging names are occupied",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn collisions_leave_existing_files_untouched_and_failures_remove_owned_files() {
        let root = std::env::temp_dir().join(format!("timed-state-write-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let result = std::panic::catch_unwind(|| {
            fs::write(root.join("unrelated"), b"keep").unwrap();
            symlink("unrelated", root.join("collision")).unwrap();
            let mut names = ["collision", "owned"].into_iter();
            replace_with(&root.join("state"), b"new", || names.next().unwrap().into()).unwrap();
            assert_eq!(fs::read(root.join("unrelated")).unwrap(), b"keep");
            assert_eq!(fs::read(root.join("state")).unwrap(), b"new");
            assert_eq!(
                fs::metadata(root.join("state"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            fs::create_dir(root.join("directory")).unwrap();
            assert!(replace_with(&root.join("directory"), b"new", || "failed".into()).is_err());
            assert!(!root.join("failed").exists());
            assert!(root.join("collision").is_symlink());
        });
        fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }
}

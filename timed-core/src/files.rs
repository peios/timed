//! Bounded reads of installed data and daemon state.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Open a regular file without waiting for a FIFO writer. Symlinks to regular
/// files remain valid, as the installed zone database uses aliases.
pub fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a regular file",
        ));
    }
    Ok(file)
}

/// Read at most `limit` bytes, checking the opened file and growth during reading.
pub fn read(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_regular(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    let mut bytes = Vec::new();
    let bound = (limit as u64).checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "file size limit is too large")
    })?;
    file.take(bound).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    Ok(bytes)
}

/// Read bounded UTF-8 text.
pub fn read_text(path: &Path, limit: usize) -> io::Result<String> {
    String::from_utf8(read(path, limit)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn regular_aliases_work_but_oversized_files_and_pipes_are_rejected() {
        let root = std::env::temp_dir().join(format!("timed-file-read-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let result = std::panic::catch_unwind(|| {
            std::fs::write(root.join("data"), b"TZif").unwrap();
            std::os::unix::fs::symlink("data", root.join("alias")).unwrap();
            assert_eq!(read(&root.join("alias"), 4).unwrap(), b"TZif");
            assert!(read(&root.join("data"), 3).is_err());
            let pipe = root.join("pipe");
            let name = CString::new(pipe.as_os_str().as_bytes()).unwrap();
            // SAFETY: name is a live, NUL-terminated path in a private test directory.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            assert!(read(&pipe, 4).is_err());
        });
        std::fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }
}

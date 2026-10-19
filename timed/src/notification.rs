//! Best-effort supervisor notifications with bounded queue wait.
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;

pub fn send(path: &Path, payload: &[u8], timeout: Duration) -> io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(timeout))?;
    let sent = socket.send_to(payload, path)?;
    if sent != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short notification",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fill_receiver(directory: &Path, path: &Path) -> Vec<UnixDatagram> {
        // Fill the receiver, not merely one sender's smaller send buffer.
        let mut senders = Vec::new();
        for index in 0..64 {
            let sender = UnixDatagram::bind(directory.join(format!("sender-{index}"))).unwrap();
            sender.set_nonblocking(true).unwrap();
            let mut count = 0;
            loop {
                match sender.send_to(b"queued", path) {
                    Ok(_) => {
                        count += 1;
                        assert!(count < 16384);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("filling queue: {error}"),
                }
            }
            senders.push(sender);
            if count == 0 {
                return senders;
            }
        }
        panic!("could not fill the supervisor queue");
    }

    #[test]
    fn a_full_supervisor_queue_cannot_hold_the_service() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "notify-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let receiver = UnixDatagram::bind(&path).unwrap();
        let senders = fill_receiver(&directory, &path);
        let (done, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            done.send(send(&path, b"READY=1", Duration::from_millis(20)))
                .unwrap();
        });
        let error = wait
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        worker.join().unwrap();
        drop((receiver, senders));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

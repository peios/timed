//! Exercise the installed-style shared boundary with disposable Unix sockets.
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use timed_client::Client;
use timed_core::{Reply, Request};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket {
    directory: PathBuf,
    path: PathBuf,
    listener: UnixListener,
}
impl Socket {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "timed-api-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        Self {
            directory,
            path,
            listener,
        }
    }
    fn client(&self) -> Client {
        Client::new(&self.path, Duration::from_secs(2)).unwrap()
    }
    fn accept(&self) -> UnixStream {
        let (stream, _) = self.listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn receive(stream: &mut UnixStream) -> Request {
    Request::decode(&timed_core::recv(stream).unwrap()).unwrap()
}
fn frame(reply: &Reply) -> Vec<u8> {
    let bytes = reply.encode();
    let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
    out.extend(bytes);
    out
}
#[test]
fn invalid_connection_settings_are_rejected() {
    assert!(Client::new("", Duration::from_secs(1)).is_err());
    assert!(Client::new("/tmp/a\0b", Duration::from_secs(1)).is_err());
    assert!(Client::new("/tmp/a", Duration::ZERO).is_err());
    assert!(Client::new("/tmp/a", Duration::MAX).is_err());
}
#[test]
fn wrong_reply_type_is_rejected() {
    let socket = Socket::new();
    let client = socket.client();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(receive(&mut stream), Request::Status);
        stream.write_all(&frame(&Reply::Ok)).unwrap();
    });
    assert_eq!(client.status().unwrap_err().code, libc::EINVAL);
    worker.join().unwrap();
}
#[test]
fn a_partial_reply_does_not_extend_the_total_deadline() {
    let socket = Socket::new();
    let client = Client::new(&socket.path, Duration::from_millis(30)).unwrap();
    let (finish, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(receive(&mut stream), Request::Status);
        stream.write_all(&[1, 0]).unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(2));
    });
    assert_eq!(client.status().unwrap_err().code, libc::ETIMEDOUT);
    finish.send(()).unwrap();
    worker.join().unwrap();
}
#[test]
fn subscription_timeout_preserves_a_partial_frame() {
    let socket = Socket::new();
    let client = socket.client();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(receive(&mut stream), Request::Subscribe);
        let bytes = frame(&Reply::Snapshot(timed_core::Snapshot {
            generation: 71,
            ..Default::default()
        }));
        stream.write_all(&bytes[..2]).unwrap();
        ready_tx.send(()).unwrap();
        finish_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        stream.write_all(&bytes[2..]).unwrap();
    });
    let mut subscription = client.subscribe().unwrap();
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        subscription
            .next(Duration::from_millis(20))
            .unwrap_err()
            .code,
        libc::ETIMEDOUT
    );
    finish_tx.send(()).unwrap();
    let snapshot = subscription.next(Duration::from_secs(2)).unwrap();
    assert_eq!(snapshot.generation, 71);
    worker.join().unwrap();
}
#[test]
fn configuration_helpers_use_the_shared_library() {
    let expected = timed_core::servers::parse_server("nts.example.test:4460").unwrap();
    assert_eq!(
        timed_client::parse_server("nts.example.test:4460").unwrap(),
        expected
    );
    assert!(timed_client::check_zone("../UTC").is_err());
    timed_client::check_zone("Europe/London").unwrap();
}

#[test]
fn zone_paths_are_validated_across_the_shared_boundary() {
    assert_eq!(
        timed_client::zone_path("Europe/London").unwrap(),
        PathBuf::from("/usr/share/zoneinfo/Europe/London")
    );
    assert_eq!(
        timed_client::zone_path("../localtime").unwrap_err().code,
        libc::EINVAL
    );
}

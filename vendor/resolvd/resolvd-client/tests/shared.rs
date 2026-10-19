//! Exercise the installed-style shared boundary with disposable Unix sockets.
use resolvd_client::Client;
use resolvd_core::{Reply, Request};
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket {
    directory: PathBuf,
    path: PathBuf,
    listener: UnixListener,
}
impl Socket {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "resolvd-api-{}-{}",
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
    Request::decode(&resolvd_core::recv(stream).unwrap()).unwrap()
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
fn lookup_returns_owned_addresses_and_provenance() {
    let socket = Socket::new();
    let client = socket.client();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(
            receive(&mut stream),
            Request::Lookup {
                name: "example.test".into(),
                family: resolvd_core::Family::Any
            }
        );
        let addresses = resolvd_core::Addresses {
            outcome: resolvd_core::Outcome::Found,
            canonical: "example.test".into(),
            addresses: vec![resolvd_core::AddressOut {
                address: "192.0.2.7".parse().unwrap(),
                ttl: 42,
            }],
            source: "test".into(),
            validation: resolvd_core::Validation::Unvalidated,
        };
        stream
            .write_all(&frame(&Reply::Addresses(addresses)))
            .unwrap();
    });
    let result = client
        .lookup("example.test", resolvd_core::Family::Any)
        .unwrap();
    worker.join().unwrap();
    drop(client);
    assert_eq!(result.canonical, "example.test");
    assert_eq!(result.source, "test");
    assert_eq!(result.addresses[0].address.to_string(), "192.0.2.7");
    assert_eq!(result.addresses[0].ttl, 42);
}

//! Exercise the installed-style shared boundary with disposable Unix sockets.
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use trust_client::Client;
use trust_core::{Reply, Request};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket {
    directory: PathBuf,
    path: PathBuf,
    listener: UnixListener,
}
impl Socket {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "trust-api-{}-{}",
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
    Request::decode(&trust_core::recv(stream).unwrap()).unwrap()
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
        assert_eq!(receive(&mut stream), Request::Subscribe { with_der: false });
        let bytes = frame(&Reply::Roots {
            generation: 71,
            roots: vec![trust_core::Root {
                subject: "Example CA".into(),
                ..Default::default()
            }],
            more: false,
        });
        stream.write_all(&bytes[..2]).unwrap();
        ready_tx.send(()).unwrap();
        finish_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        stream.write_all(&bytes[2..]).unwrap();
    });
    let mut subscription = client.subscribe(false).unwrap();
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
fn roots_from_different_generations_are_not_combined() {
    let socket = Socket::new();
    let client = socket.client();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        receive(&mut stream);
        stream
            .write_all(&frame(&Reply::Roots {
                generation: 1,
                roots: vec![],
                more: true,
            }))
            .unwrap();
        stream
            .write_all(&frame(&Reply::Roots {
                generation: 2,
                roots: vec![],
                more: false,
            }))
            .unwrap();
    });
    assert_eq!(client.roots(false, None).unwrap_err().code, libc::EINVAL);
    worker.join().unwrap();
}
#[test]
fn certificate_details_cross_the_shared_boundary() {
    let pem = include_bytes!("../../trust-core/tests/fixtures/comodo-ecc.pem");
    let der = trust_client::certificate(pem, "fixture").unwrap();
    let expected = trust_core::cert::describe(&der).unwrap();
    let actual = trust_client::inspect(&der).unwrap();
    assert_eq!(actual.subject, expected.subject);
    assert_eq!(actual.serial, expected.serial);
    assert!(actual.ca);
    assert!(!actual.subject.is_empty());
}

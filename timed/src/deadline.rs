//! Socket I/O under one monotonic operation deadline.
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub(crate) fn remaining(end: Instant) -> io::Result<Duration> {
    end.checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "NTS handshake timed out"))
}

pub(crate) struct Stream {
    socket: TcpStream,
    end: Instant,
}

impl Stream {
    pub(crate) fn new(socket: TcpStream, end: Instant) -> Self {
        Self { socket, end }
    }
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(remaining(self.end)?))?;
        self.socket.read(bytes)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(remaining(self.end)?))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.set_write_timeout(Some(remaining(self.end)?))?;
        self.socket.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn an_expired_deadline_refuses_ready_reads_and_writes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.write_all(b"ready").unwrap();
        let mut stream = Stream::new(socket, Instant::now());
        assert_eq!(
            stream.read(&mut [0; 8]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write(b"request").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(stream.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}

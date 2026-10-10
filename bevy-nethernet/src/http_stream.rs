use crate::http_client::JoinError;
use crate::tcp_wire::{Inbound, Wire, WireError};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};

#[cfg(feature = "tls")]
use std::sync::Arc;

/// Outcome of one attempt to write the queued outbound bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Drain {
    Empty,
    Blocked,
    Partial,
    Complete,
}

/// Outcome of one attempt to finish the connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Shutdown {
    Pending,
    Done,
}

/// A non-blocking HTTP connection: a wire plus its inbound and outbound buffers.
pub(crate) struct HttpStream {
    wire: Wire,
    pub(crate) inbound: Vec<u8>,
    outbound: Vec<u8>,
    written: usize,
}

impl HttpStream {
    pub(crate) fn new(wire: Wire) -> Self {
        Self {
            wire,
            inbound: Vec::new(),
            outbound: Vec::new(),
            written: 0,
        }
    }

    pub(crate) fn queue(&mut self, bytes: &[u8]) {
        self.outbound.extend_from_slice(bytes);
    }

    pub(crate) fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    pub(crate) fn fill(&mut self) -> Result<Inbound, WireError> {
        self.wire.read(&mut self.inbound)
    }

    pub(crate) fn drain(&mut self) -> Result<Drain, WireError> {
        if self.outbound.is_empty() {
            return Ok(Drain::Empty);
        }
        match self.wire.write(&self.outbound[self.written..]) {
            Ok(0) => Err(WireError::WriteZero),
            Ok(accepted) => {
                self.written += accepted;
                if self.written == self.outbound.len() {
                    self.outbound.clear();
                    self.written = 0;
                    Ok(Drain::Complete)
                } else {
                    Ok(Drain::Partial)
                }
            }
            Err(WireError::Io(e)) if e.kind() == ErrorKind::WouldBlock => Ok(Drain::Blocked),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn flush(&mut self) -> Result<(), WireError> {
        self.wire.flush()
    }

    pub(crate) fn close(&mut self) -> Shutdown {
        if self.wire.finish().is_err() || !self.wire.has_pending_output() {
            Shutdown::Done
        } else {
            Shutdown::Pending
        }
    }

    /// Starts the TLS session of an accepted connection once the plaintext preamble is
    /// consumed, handing it whatever was already read.
    #[cfg(feature = "tls")]
    pub(crate) fn establish(&mut self) -> Result<Inbound, WireError> {
        if !self.wire.awaiting_session() {
            return Ok(Inbound::Idle);
        }
        let leftover = std::mem::take(&mut self.inbound);
        self.wire.begin_session(leftover)?;
        self.wire.read(&mut self.inbound)
    }

    #[cfg(not(feature = "tls"))]
    pub(crate) fn establish(&mut self) -> Result<Inbound, WireError> {
        Ok(Inbound::Idle)
    }

    fn connect_socket(addr: SocketAddr) -> std::io::Result<TcpStream> {
        let socket = Socket::new(
            Domain::for_address(addr),
            Type::STREAM,
            Some(SocketProtocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            Err(e) if Self::connect_in_progress(&e) => {}
            Err(e) => return Err(e),
        }
        Ok(socket.into())
    }

    /// A non-blocking `connect()` reports that it hasn't completed yet as `EWOULDBLOCK` on
    /// Windows (mapped to [`ErrorKind::WouldBlock`]), but as `EINPROGRESS` on Unix, which
    /// `ErrorKind` has no variant for.
    fn connect_in_progress(e: &std::io::Error) -> bool {
        if e.kind() == ErrorKind::WouldBlock {
            return true;
        }
        #[cfg(unix)]
        {
            e.raw_os_error() == Some(libc::EINPROGRESS)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// The TLS configuration a server wraps accepted connections in, if any.
#[derive(Clone, Default)]
pub(crate) struct ServerTls {
    #[cfg(feature = "tls")]
    config: Option<Arc<rustls::ServerConfig>>,
}

impl ServerTls {
    #[cfg(feature = "tls")]
    pub(crate) fn with_config(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            config: Some(config),
        }
    }

    pub(crate) fn accept(&self, stream: TcpStream) -> HttpStream {
        #[cfg(feature = "tls")]
        if let Some(config) = &self.config {
            return HttpStream::new(Wire::tls(stream, config.clone()));
        }
        HttpStream::new(Wire::plain(stream))
    }
}

/// The TLS configuration a client dials secure targets with, if any.
#[derive(Clone, Default)]
pub(crate) struct ClientTls {
    #[cfg(feature = "tls")]
    config: Option<Arc<rustls::ClientConfig>>,
}

impl ClientTls {
    #[cfg(feature = "tls")]
    pub(crate) fn with_config(config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            config: Some(config),
        }
    }

    pub(crate) fn dial(
        &self,
        secure: bool,
        host: &str,
        addr: SocketAddr,
    ) -> std::io::Result<HttpStream> {
        let wire = match secure {
            true => self.secure_wire(host, addr)?,
            false => Wire::plain(HttpStream::connect_socket(addr)?),
        };
        Ok(HttpStream::new(wire))
    }

    #[cfg(feature = "tls")]
    fn secure_wire(&self, host: &str, addr: SocketAddr) -> std::io::Result<Wire> {
        let config = match &self.config {
            Some(config) => config.clone(),
            None => Self::platform_config().map_err(JoinError::from)?,
        };
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| JoinError::InvalidServerName)?;
        let wire = Wire::tls_client(HttpStream::connect_socket(addr)?, config, name)
            .map_err(JoinError::from)?;
        Ok(wire)
    }

    #[cfg(not(feature = "tls"))]
    fn secure_wire(&self, _host: &str, _addr: SocketAddr) -> std::io::Result<Wire> {
        Err(JoinError::TlsUnavailable.into())
    }

    #[cfg(feature = "tls")]
    fn platform_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_platform_verifier()?
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn loopback_pair() -> (HttpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        local.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        (HttpStream::new(Wire::plain(local)), peer)
    }

    #[test]
    fn fill_is_idle_until_the_peer_writes() {
        let (mut stream, mut peer) = loopback_pair();
        assert_eq!(stream.fill().unwrap(), Inbound::Idle);

        peer.write_all(b"GET /").unwrap();
        let mut received = Inbound::Idle;
        for _ in 0..1000 {
            received = stream.fill().unwrap();
            if received == Inbound::Received {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(received, Inbound::Received);
        assert_eq!(stream.inbound, b"GET /");
    }

    #[test]
    fn fill_reports_closed_when_the_peer_hangs_up() {
        let (mut stream, peer) = loopback_pair();
        drop(peer);
        let mut last = Inbound::Idle;
        for _ in 0..1000 {
            last = stream.fill().unwrap();
            if last == Inbound::Closed {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(last, Inbound::Closed);
    }

    #[test]
    fn drain_delivers_a_large_payload_intact() {
        let (mut stream, mut peer) = loopback_pair();
        let payload: Vec<u8> = (0..16 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        stream.queue(&payload);
        assert!(stream.has_outbound());

        let mut received = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        for _ in 0..1_000_000 {
            if stream.has_outbound() {
                stream.drain().unwrap();
            }
            match peer.read(&mut chunk) {
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("peer read failed: {e}"),
            }
            if received.len() == payload.len() {
                break;
            }
        }
        assert!(!stream.has_outbound());
        assert_eq!(received, payload, "payload corrupted across drains");
    }

    #[test]
    fn drain_is_empty_without_queued_bytes() {
        let (mut stream, _peer) = loopback_pair();
        assert_eq!(stream.drain().unwrap(), Drain::Empty);
    }

    #[test]
    fn close_is_done_on_a_plain_wire() {
        let (mut stream, _peer) = loopback_pair();
        assert_eq!(stream.close(), Shutdown::Done);
    }
}

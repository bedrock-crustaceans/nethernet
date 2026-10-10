use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

#[cfg(feature = "tls")]
use std::sync::Arc;

const READ_CHUNK: usize = 4096;
#[cfg(feature = "tls")]
const MAX_READS_PER_TICK: usize = 16;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WireError {
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "tls")]
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    #[cfg(feature = "tls")]
    #[error("the tls handshake has not begun")]
    TlsNotStarted,
    #[error("the peer accepted no bytes")]
    WriteZero,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Inbound {
    Received,
    Idle,
    Closed,
}

pub(crate) enum Wire {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(TlsWire),
}

#[cfg(feature = "tls")]
pub(crate) struct TlsWire {
    stream: TcpStream,
    config: Option<Arc<rustls::ServerConfig>>,
    session: Option<Box<rustls::Connection>>,
    staged: Vec<u8>,
    closing: bool,
}

impl Wire {
    pub(crate) fn plain(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }

    #[cfg(feature = "tls")]
    pub(crate) fn tls(stream: TcpStream, config: Arc<rustls::ServerConfig>) -> Self {
        Self::Tls(TlsWire {
            stream,
            config: Some(config),
            session: None,
            staged: Vec::new(),
            closing: false,
        })
    }

    #[cfg(feature = "tls")]
    pub(crate) fn tls_client(
        stream: TcpStream,
        config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<Self, rustls::Error> {
        let session = rustls::ClientConnection::new(config, server_name)?;
        Ok(Self::Tls(TlsWire {
            stream,
            config: None,
            session: Some(Box::new(rustls::Connection::Client(session))),
            staged: Vec::new(),
            closing: false,
        }))
    }

    #[cfg(feature = "tls")]
    pub(crate) fn awaiting_session(&self) -> bool {
        matches!(self, Self::Tls(tls) if tls.session.is_none())
    }

    #[cfg(feature = "tls")]
    pub(crate) fn begin_session(&mut self, leftover: Vec<u8>) -> Result<(), WireError> {
        if let Self::Tls(tls) = self
            && let Some(config) = tls.config.clone()
        {
            let session = rustls::ServerConnection::new(config)?;
            tls.session = Some(Box::new(rustls::Connection::Server(session)));
            tls.staged = leftover;
        }
        Ok(())
    }

    fn read_raw(stream: &mut TcpStream, into: &mut Vec<u8>) -> Result<Inbound, WireError> {
        let mut chunk = [0u8; READ_CHUNK];
        match stream.read(&mut chunk) {
            Ok(0) => Ok(Inbound::Closed),
            Ok(n) => {
                into.extend_from_slice(&chunk[..n]);
                Ok(Inbound::Received)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(Inbound::Idle),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn read(&mut self, into: &mut Vec<u8>) -> Result<Inbound, WireError> {
        match self {
            Self::Plain(stream) => Self::read_raw(stream, into),
            #[cfg(feature = "tls")]
            Self::Tls(tls) => tls.read(into),
        }
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> Result<usize, WireError> {
        match self {
            Self::Plain(stream) => Ok(stream.write(data)?),
            #[cfg(feature = "tls")]
            Self::Tls(tls) => tls.write(data),
        }
    }

    pub(crate) fn flush(&mut self) -> Result<(), WireError> {
        match self {
            Self::Plain(_) => Ok(()),
            #[cfg(feature = "tls")]
            Self::Tls(tls) => tls.flush(),
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), WireError> {
        match self {
            Self::Plain(_) => Ok(()),
            #[cfg(feature = "tls")]
            Self::Tls(tls) => tls.finish(),
        }
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            #[cfg(feature = "tls")]
            Self::Tls(tls) => tls.session.as_ref().is_some_and(|s| s.wants_write()),
        }
    }
}

#[cfg(feature = "tls")]
impl TlsWire {
    fn read(&mut self, into: &mut Vec<u8>) -> Result<Inbound, WireError> {
        let Some(session) = self.session.as_mut() else {
            return Wire::read_raw(&mut self.stream, into);
        };

        let mut received = false;
        let mut eof = false;
        for _ in 0..MAX_READS_PER_TICK {
            let mut starved = false;
            if !self.staged.is_empty() {
                let consumed = session.read_tls(&mut self.staged.as_slice())?;
                self.staged.drain(..consumed);
            } else if session.wants_read() {
                match session.read_tls(&mut self.stream) {
                    Ok(0) => eof = true,
                    Ok(_) => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => starved = true,
                    Err(e) => return Err(e.into()),
                }
            } else {
                starved = true;
            }

            if let Err(error) = session.process_new_packets() {
                let _ = Self::flush_session(session, &mut self.stream);
                return Err(error.into());
            }

            let mut chunk = [0u8; READ_CHUNK];
            loop {
                match session.reader().read(&mut chunk) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        into.extend_from_slice(&chunk[..n]);
                        received = true;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }

            if eof || (starved && self.staged.is_empty()) {
                break;
            }
        }

        Self::flush_session(session, &mut self.stream)?;
        Ok(match (received, eof) {
            (true, _) => Inbound::Received,
            (false, true) => Inbound::Closed,
            (false, false) => Inbound::Idle,
        })
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, WireError> {
        let session = self.session.as_mut().ok_or(WireError::TlsNotStarted)?;
        let accepted = session.writer().write(data)?;
        Self::flush_session(session, &mut self.stream)?;
        Ok(accepted)
    }

    fn flush(&mut self) -> Result<(), WireError> {
        match self.session.as_mut() {
            Some(session) => Self::flush_session(session, &mut self.stream),
            None => Ok(()),
        }
    }

    fn finish(&mut self) -> Result<(), WireError> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        if !self.closing {
            self.closing = true;
            session.send_close_notify();
        }
        Self::flush_session(session, &mut self.stream)
    }

    fn flush_session(
        session: &mut rustls::Connection,
        stream: &mut TcpStream,
    ) -> Result<(), WireError> {
        while session.wants_write() {
            match session.write_tls(stream) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

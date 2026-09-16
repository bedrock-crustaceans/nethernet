use crate::socket::local_bind_addr;
use nethernet::connection::Connection;
use nethernet::error::ProtocolError;
use nethernet::protocol::Signal;
use nethernet::session::{Channel, SessionEvent, SessionOutput};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

const MAX_DATAGRAMS_PER_TICK: usize = 256;

pub(crate) enum ConnectionEvent {
    Ready,
    Message(Channel, Box<[u8]>),
}

pub(crate) fn bind_session_socket() -> std::io::Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind(local_bind_addr())?;
    socket.set_nonblocking(true)?;
    let addr = socket.local_addr()?;
    Ok((socket, addr))
}

pub(crate) struct ConnectionDriver {
    connection: Connection,
    socket: UdpSocket,
    buf: Box<[u8]>,
}

impl ConnectionDriver {
    pub(crate) fn new(socket: UdpSocket, connection: Connection) -> Self {
        Self {
            connection,
            socket,
            buf: vec![0u8; 65536].into_boxed_slice(),
        }
    }

    pub(crate) fn handle_signal(&mut self, signal: &Signal) -> Result<(), ProtocolError> {
        self.connection.handle_signal(signal)
    }

    pub(crate) fn send(&mut self, channel: Channel, data: Box<[u8]>) -> Result<(), ProtocolError> {
        self.connection.send(channel, data.into())
    }

    pub(crate) fn drive(&mut self, now: Instant, events: &mut Vec<ConnectionEvent>) {
        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match self.socket.recv_from(&mut self.buf) {
                Ok((len, from)) => {
                    if let Err(e) = self.connection.handle_packet(&self.buf[..len], from, now) {
                        tracing::debug!("packet handling error: {e}");
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::debug!("recv error: {e}");
                    break;
                }
            }
        }

        if let Err(e) = self.connection.handle_timeout(now) {
            tracing::debug!("timeout handling error: {e}");
        }

        while let Some(output) = self.connection.poll() {
            match output {
                SessionOutput::Send(data, to) => {
                    let _ = self.socket.send_to(&data, to);
                }
                SessionOutput::Event(SessionEvent::Ready) => events.push(ConnectionEvent::Ready),
                SessionOutput::Message(channel, data) => {
                    events.push(ConnectionEvent::Message(channel, data.into_boxed_slice()))
                }
            }
        }
    }
}

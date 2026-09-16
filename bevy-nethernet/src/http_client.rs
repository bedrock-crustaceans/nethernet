use crate::connection::{ConnectionDriver, ConnectionEvent, bind_session_socket};
use crate::http_wire;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{Connection, IceMode};
use nethernet::error::ProtocolError;
use nethernet::protocol::Signal;
use nethernet::session::{Channel, Session};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_CHUNK: usize = 4096;

pub struct NethernetHttpClientPlugin;

impl Plugin for NethernetHttpClientPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NethernetHttpClientEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NethernetHttpClientSet)
                .run_if(resource_exists::<NethernetHttpClient>),
        );
    }
}

impl NethernetHttpClientPlugin {
    fn update(
        mut client: ResMut<NethernetHttpClient>,
        mut events: MessageWriter<NethernetHttpClientEvent>,
    ) {
        client.update();

        while let Some(event) = client.next_event() {
            events.write(event);
        }
    }
}

/// PreUpdate set containing NethernetHttpClientPlugin's update system. Order your own
/// systems `.after(NethernetHttpClientSet)` to see this tick's events/received data.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NethernetHttpClientSet;

#[derive(Message, Clone, Copy, Debug)]
pub enum NethernetHttpClientEvent {
    Connected,
    ConnectFailed,
    Disconnected,
}

enum JoinState {
    Sending {
        socket: Socket,
        request: Vec<u8>,
        written: usize,
    },
    Receiving {
        socket: Socket,
        buf: Vec<u8>,
    },
}

enum JoinStep {
    Pending(JoinState),
    Done(u16, String),
    Failed,
}

fn drive_join(state: JoinState) -> JoinStep {
    match state {
        JoinState::Sending {
            mut socket,
            request,
            mut written,
        } => match socket.write(&request[written..]) {
            Ok(0) => JoinStep::Failed,
            Ok(n) => {
                written += n;
                if written == request.len() {
                    JoinStep::Pending(JoinState::Receiving {
                        socket,
                        buf: Vec::new(),
                    })
                } else {
                    JoinStep::Pending(JoinState::Sending {
                        socket,
                        request,
                        written,
                    })
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => JoinStep::Pending(JoinState::Sending {
                socket,
                request,
                written,
            }),
            Err(_) => JoinStep::Failed,
        },
        JoinState::Receiving {
            mut socket,
            mut buf,
        } => {
            let mut chunk = [0u8; READ_CHUNK];
            match socket.read(&mut chunk) {
                Ok(0) => JoinStep::Failed,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    match http_wire::parse_response(&buf) {
                        Ok(Some((code, body))) => JoinStep::Done(code, body),
                        Ok(None) if buf.len() > http_wire::MAX_BODY => JoinStep::Failed,
                        Ok(None) => JoinStep::Pending(JoinState::Receiving { socket, buf }),
                        Err(_) => JoinStep::Failed,
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    JoinStep::Pending(JoinState::Receiving { socket, buf })
                }
                Err(_) => JoinStep::Failed,
            }
        }
    }
}

struct Join {
    state: JoinState,
    connection: Connection,
    session_socket: UdpSocket,
    server_url: String,
}

#[derive(Resource, Default)]
pub struct NethernetHttpClient {
    join: Option<Join>,
    connection: Option<ConnectionDriver>,
    connecting_since: Option<Instant>,
    ready: bool,
    events: VecDeque<NethernetHttpClientEvent>,
    received: VecDeque<Box<[u8]>>,
    received_unreliable: VecDeque<Box<[u8]>>,
}

impl NethernetHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_connected(&self) -> bool {
        self.ready
    }

    /// Starts joining the server at `server_url` (e.g. `http://example.com:19132`).
    /// Only plain HTTP is supported. Replaces any join or connection in progress.
    pub fn connect(&mut self, local_network_id: String, server_url: String) -> std::io::Result<()> {
        self.join = None;
        self.connection = None;
        self.ready = false;

        let host = server_url.strip_prefix("http://").ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "only http:// URLs are supported")
        })?;
        let addr = host
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "could not resolve host"))?;

        let (session_socket, local_addr) = bind_session_socket()?;
        let (session, description) =
            Session::new(local_addr, true).map_err(std::io::Error::other)?;

        let connection_id = rand::random::<u64>();
        let (connection, signals) = Connection::connect(
            session,
            description,
            connection_id,
            server_url.clone(),
            IceMode::Full,
        );
        let offer = signals
            .into_iter()
            .next()
            .expect("Connection::connect always returns an offer first");

        let request = http_wire::encode_post(
            host,
            &format!("/v1/join/{local_network_id}"),
            "application/sdp",
            &offer.data,
        );

        let socket = connect(addr)?;

        self.join = Some(Join {
            state: JoinState::Sending {
                socket,
                request,
                written: 0,
            },
            connection,
            session_socket,
            server_url,
        });
        self.connecting_since = Some(Instant::now());
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.join = None;
        self.connection = None;
        self.connecting_since = None;
        if self.ready {
            self.ready = false;
            self.events
                .push_back(NethernetHttpClientEvent::Disconnected);
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.send_on(Channel::Reliable, data)
    }

    pub fn send_unreliable(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.send_on(Channel::Unreliable, data)
    }

    fn send_on(&mut self, channel: Channel, data: &[u8]) -> Result<(), ProtocolError> {
        let Some(connection) = self.connection.as_mut() else {
            return Err(ProtocolError::Other("not connected".to_string()));
        };
        connection.send(channel, data.into())
    }

    pub fn recv(&mut self) -> Option<Box<[u8]>> {
        self.received.pop_front()
    }

    pub fn recv_unreliable(&mut self) -> Option<Box<[u8]>> {
        self.received_unreliable.pop_front()
    }

    pub fn next_event(&mut self) -> Option<NethernetHttpClientEvent> {
        self.events.pop_front()
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        if let Some(mut join) = self.join.take() {
            match drive_join(join.state) {
                JoinStep::Pending(state) => {
                    join.state = state;
                    self.join = Some(join);
                }
                JoinStep::Done(code, body) if (200..300).contains(&code) => {
                    if body.trim().parse::<u32>().is_ok() {
                        tracing::debug!("server rejected the offer: {body}");
                        self.connecting_since = None;
                        self.events
                            .push_back(NethernetHttpClientEvent::ConnectFailed);
                    } else {
                        let Join {
                            mut connection,
                            session_socket,
                            server_url,
                            ..
                        } = join;
                        let answer = Signal::answer(connection.connection_id(), body, server_url);
                        if connection.handle_signal(&answer).is_ok() {
                            self.connection =
                                Some(ConnectionDriver::new(session_socket, connection));
                        } else {
                            self.connecting_since = None;
                            self.events
                                .push_back(NethernetHttpClientEvent::ConnectFailed);
                        }
                    }
                }
                JoinStep::Done(..) | JoinStep::Failed => {
                    self.connecting_since = None;
                    self.events
                        .push_back(NethernetHttpClientEvent::ConnectFailed);
                }
            }
        }

        if let Some(connection) = self.connection.as_mut() {
            let mut events = Vec::new();
            connection.drive(now, &mut events);

            for event in events {
                match event {
                    ConnectionEvent::Ready if !self.ready => {
                        self.ready = true;
                        self.connecting_since = None;
                        self.events.push_back(NethernetHttpClientEvent::Connected);
                    }
                    ConnectionEvent::Ready => {}
                    ConnectionEvent::Message(Channel::Reliable, data) => {
                        self.received.push_back(data)
                    }
                    ConnectionEvent::Message(Channel::Unreliable, data) => {
                        self.received_unreliable.push_back(data)
                    }
                    ConnectionEvent::Failed => {
                        let was_ready = self.ready;
                        self.join = None;
                        self.connection = None;
                        self.connecting_since = None;
                        self.ready = false;
                        self.events.push_back(if was_ready {
                            NethernetHttpClientEvent::Disconnected
                        } else {
                            NethernetHttpClientEvent::ConnectFailed
                        });
                    }
                }
            }
        }

        if let Some(since) = self.connecting_since
            && now.saturating_duration_since(since) >= CONNECT_TIMEOUT
        {
            let was_ready = self.ready;
            self.join = None;
            self.connection = None;
            self.connecting_since = None;
            self.ready = false;
            self.events.push_back(if was_ready {
                NethernetHttpClientEvent::Disconnected
            } else {
                NethernetHttpClientEvent::ConnectFailed
            });
        }
    }
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

fn connect(addr: SocketAddr) -> std::io::Result<Socket> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if connect_in_progress(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(socket)
}

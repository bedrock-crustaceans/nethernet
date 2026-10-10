use crate::connection::{ConnectionEvent, SessionPool};
use crate::http_stream::{ClientTls, Drain, HttpStream};
use crate::http_wire;
use crate::socket::bind_shared_socket;
use crate::tcp_wire::Inbound;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use bevy_platform::cell::SyncCell;
use nethernet::connection::{Connection, ConnectionInput, IceMode, Timeouts};
use nethernet::error::ProtocolError;
use nethernet::prelude::ServerData;
use nethernet::prelude::ServerIdentity;
use nethernet::protocol::Signal;
use nethernet::sans::Sans;
use nethernet::session::{Channel, Session};
use nethernet::signaling::http::join::{self, StatusResponseError};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct NetherHttpClientPlugin;

impl Plugin for NetherHttpClientPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherHttpClientEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherHttpClientSet)
                .run_if(resource_exists::<NetherHttpClient>),
        );
    }
}

impl NetherHttpClientPlugin {
    fn update(
        mut client: ResMut<NetherHttpClient>,
        mut events: MessageWriter<NetherHttpClientEvent>,
    ) {
        client.update();

        while let Some(event) = client.next_event() {
            events.write(event);
        }
    }
}

#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherHttpClientSet;

#[derive(Message, Debug)]
pub enum NetherHttpClientEvent {
    Connected,
    ConnectFailed,
    Disconnected,
    ServerData(Box<ServerData>),
    QueryFailed(QueryError),
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("the connection to the server failed")]
    Connection,
    #[error("the server did not answer in time")]
    TimedOut,
    #[error(transparent)]
    Response(#[from] StatusResponseError),
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("the server url has no scheme")]
    MissingScheme,
    #[error("only http and https server urls are supported")]
    UnsupportedScheme,
    #[error("the server url has no host")]
    MissingHost,
    #[error("the server url has an invalid port")]
    InvalidPort,
    #[error("https joins need the tls feature")]
    TlsUnavailable,
    #[cfg(feature = "tls")]
    #[error("the server url host is not a valid tls server name")]
    InvalidServerName,
    #[cfg(feature = "tls")]
    #[error("tls setup failed: {0}")]
    Tls(#[from] rustls::Error),
}

impl From<JoinError> for std::io::Error {
    fn from(error: JoinError) -> Self {
        std::io::Error::new(ErrorKind::InvalidInput, error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JoinTarget {
    secure: bool,
    host: String,
    port: u16,
    authority: String,
}

impl JoinTarget {
    fn parse(url: &str) -> Result<Self, JoinError> {
        let (scheme, rest) = url.split_once("://").ok_or(JoinError::MissingScheme)?;
        let (secure, default_port) = match scheme.to_ascii_lowercase().as_str() {
            "http" => (false, 80),
            "https" => (true, 443),
            _ => return Err(JoinError::UnsupportedScheme),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host_and_port = authority.rsplit('@').next().unwrap_or_default();
        let (host, port_text) = match host_and_port.strip_prefix('[') {
            Some(bracketed) => {
                let (host, after) = bracketed.split_once(']').ok_or(JoinError::MissingHost)?;
                (host, after.strip_prefix(':'))
            }
            None => match host_and_port.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_and_port, None),
            },
        };
        if host.is_empty() {
            return Err(JoinError::MissingHost);
        }
        let port = match port_text {
            Some(text) => text.parse().map_err(|_| JoinError::InvalidPort)?,
            None => default_port,
        };
        Ok(Self {
            secure,
            host: host.to_string(),
            port,
            authority: host_and_port.to_string(),
        })
    }
}

enum JoinState {
    Sending(HttpStream),
    Receiving(HttpStream),
}

impl JoinState {
    fn sending(mut stream: HttpStream, request: &[u8]) -> Self {
        stream.queue(request);
        Self::Sending(stream)
    }
}

enum JoinStep {
    Pending(JoinState),
    Done(u16, String),
    Failed,
}

fn drive_join(state: JoinState) -> JoinStep {
    match state {
        JoinState::Sending(mut stream) => match stream.drain() {
            Ok(Drain::Blocked | Drain::Partial) => JoinStep::Pending(JoinState::Sending(stream)),
            Ok(Drain::Complete | Drain::Empty) => JoinStep::Pending(JoinState::Receiving(stream)),
            Err(_) => JoinStep::Failed,
        },
        JoinState::Receiving(mut stream) => match stream.fill() {
            Ok(Inbound::Closed) | Err(_) => JoinStep::Failed,
            Ok(Inbound::Idle) => JoinStep::Pending(JoinState::Receiving(stream)),
            Ok(Inbound::Received) => match http_wire::ResponseReader::parse(&stream.inbound) {
                Ok(http_wire::Parsed::Complete(response)) => {
                    let (parts, body) = response.into_parts();
                    match http_wire::TextBody::decode(body) {
                        Ok(body) => JoinStep::Done(parts.status.as_u16(), body),
                        Err(_) => JoinStep::Failed,
                    }
                }
                Ok(http_wire::Parsed::Partial) if stream.inbound.len() > http_wire::MAX_BODY => {
                    JoinStep::Failed
                }
                Ok(http_wire::Parsed::Partial) => JoinStep::Pending(JoinState::Receiving(stream)),
                Err(_) => JoinStep::Failed,
            },
        },
    }
}

struct Join {
    state: JoinState,
    connection: SyncCell<Connection>,
    local_ufrag: String,
    session_socket: UdpSocket,
    server_url: String,
}

struct Query {
    state: JoinState,
    deadline: Instant,
}

const DEFAULT_ATTEMPTS: u32 = 3;

#[derive(Resource)]
pub struct NetherHttpClient {
    join: Option<Join>,
    query: Option<Query>,
    pool: Option<SessionPool<()>>,
    connected: bool,
    connecting_deadline: Option<Instant>,
    timeouts: Timeouts,
    attempts: u32,
    attempts_left: u32,
    local_network_id: String,
    server_url: String,
    ready: bool,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    identity: Option<ServerIdentity>,
    tls: ClientTls,
    events: VecDeque<NetherHttpClientEvent>,
    received: VecDeque<Box<[u8]>>,
    received_unreliable: VecDeque<Box<[u8]>>,
}

impl Default for NetherHttpClient {
    fn default() -> Self {
        Self {
            join: None,
            query: None,
            pool: None,
            connected: false,
            connecting_deadline: None,
            timeouts: Timeouts::default(),
            attempts: DEFAULT_ATTEMPTS,
            attempts_left: 0,
            local_network_id: String::new(),
            server_url: String::new(),
            ready: false,
            remote_addr: None,
            rtt: None,
            identity: None,
            tls: ClientTls::default(),
            events: VecDeque::new(),
            received: VecDeque::new(),
            received_unreliable: VecDeque::new(),
        }
    }
}

impl NetherHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    pub fn query_server_data(&mut self, url: &str) -> std::io::Result<()> {
        let (target, addr) = Self::resolve(url)?;
        let stream = self.open_stream(&target, addr)?;
        let request = http_wire::RequestWriter::get(&target.authority, join::STATUS_PATH)
            .map_err(std::io::Error::other)?;
        self.query = Some(Query {
            state: JoinState::sending(stream, &request),
            deadline: Instant::now() + self.timeouts.negotiation,
        });
        Ok(())
    }

    fn resolve(url: &str) -> std::io::Result<(JoinTarget, SocketAddr)> {
        let target = JoinTarget::parse(url)?;
        let addr = (target.host.as_str(), target.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "could not resolve host"))?;
        Ok((target, addr))
    }

    fn update_query(&mut self, now: Instant) {
        let Some(query) = self.query.take() else {
            return;
        };
        let Query { state, deadline } = query;
        match drive_join(state) {
            JoinStep::Pending(_) if now >= deadline => self
                .events
                .push_back(NetherHttpClientEvent::QueryFailed(QueryError::TimedOut)),
            JoinStep::Pending(state) => self.query = Some(Query { state, deadline }),
            JoinStep::Done(code, body) => self.events.push_back(
                match join::validate_status_response(code, body.as_bytes()) {
                    Ok(data) => NetherHttpClientEvent::ServerData(Box::new(data)),
                    Err(e) => NetherHttpClientEvent::QueryFailed(e.into()),
                },
            ),
            JoinStep::Failed => self
                .events
                .push_back(NetherHttpClientEvent::QueryFailed(QueryError::Connection)),
        }
    }

    pub fn set_attempts(&mut self, attempts: u32) {
        self.attempts = attempts;
    }

    #[cfg(feature = "tls")]
    pub fn set_tls_config(&mut self, config: Arc<rustls::ClientConfig>) {
        self.tls = ClientTls::with_config(config);
    }

    pub fn is_connected(&self) -> bool {
        self.ready
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    pub fn connect(&mut self, local_network_id: String, server_url: String) -> std::io::Result<()> {
        self.join = None;
        self.pool = None;
        self.connected = false;
        self.ready = false;
        self.remote_addr = None;
        self.rtt = None;

        self.local_network_id = local_network_id;
        self.server_url = server_url;
        self.attempts_left = self.attempts.max(1);
        self.begin_join()
    }

    fn begin_join(&mut self) -> std::io::Result<()> {
        self.attempts_left = self.attempts_left.saturating_sub(1);
        let server_url = self.server_url.clone();
        let (target, addr) = Self::resolve(&server_url)?;

        let (session_socket, local_addr) = bind_shared_socket()?;
        let (session, description) =
            Session::new(local_addr, true, Instant::now()).map_err(std::io::Error::other)?;
        let local_ufrag = description.ice.ufrag.clone();

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

        let offer_data = match &self.identity {
            Some(identity) => identity
                .augment(&offer.data)
                .map_err(std::io::Error::other)?,
            None => offer.data,
        };

        let request = http_wire::RequestWriter::post(
            &target.authority,
            &join::join_path(&self.local_network_id),
            join::CONTENT_TYPE,
            &offer_data,
        )
        .map_err(std::io::Error::other)?;

        let stream = self.open_stream(&target, addr)?;

        self.join = Some(Join {
            state: JoinState::sending(stream, &request),
            connection: SyncCell::new(connection),
            local_ufrag,
            session_socket,
            server_url,
        });
        self.connecting_deadline = Some(Instant::now() + self.timeouts.negotiation);
        Ok(())
    }

    fn open_stream(&self, target: &JoinTarget, addr: SocketAddr) -> std::io::Result<HttpStream> {
        self.tls.dial(target.secure, &target.host, addr)
    }

    pub fn disconnect(&mut self) {
        self.join = None;
        self.pool = None;
        self.connected = false;
        self.connecting_deadline = None;
        if self.ready {
            self.ready = false;
            self.remote_addr = None;
            self.rtt = None;
            self.events.push_back(NetherHttpClientEvent::Disconnected);
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.send_on(Channel::Reliable, data)
    }

    pub fn send_unreliable(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.send_on(Channel::Unreliable, data)
    }

    fn send_on(&mut self, channel: Channel, data: &[u8]) -> Result<(), ProtocolError> {
        if !self.connected {
            return Err(ProtocolError::Other("not connected".to_string()));
        }
        self.pool.as_mut().unwrap().send((), channel, data.into());
        Ok(())
    }

    pub fn recv(&mut self) -> Option<Box<[u8]>> {
        self.received.pop_front()
    }

    pub fn recv_unreliable(&mut self) -> Option<Box<[u8]>> {
        self.received_unreliable.pop_front()
    }

    pub fn next_event(&mut self) -> Option<NetherHttpClientEvent> {
        self.events.pop_front()
    }

    pub fn update(&mut self) {
        let now = Instant::now();
        self.update_query(now);

        if let Some(mut join) = self.join.take() {
            match drive_join(join.state) {
                JoinStep::Pending(state) => {
                    join.state = state;
                    self.join = Some(join);
                }
                JoinStep::Done(code, body) => match join::validate_join_response(code, &body) {
                    Ok(()) => {
                        let Join {
                            connection,
                            local_ufrag,
                            session_socket,
                            server_url,
                            ..
                        } = join;
                        let mut connection = SyncCell::to_inner(connection);
                        let answer = Signal::answer(connection.connection_id(), body, server_url);

                        if connection
                            .handle(ConnectionInput::Signal(answer, now))
                            .is_ok()
                        {
                            let mut pool = SessionPool::new(session_socket);
                            pool.add((), connection, local_ufrag);
                            self.pool = Some(pool);
                            self.connected = true;
                            self.connecting_deadline = Some(now + self.timeouts.establish());
                        } else {
                            self.connecting_deadline = None;
                            self.events.push_back(NetherHttpClientEvent::ConnectFailed);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("join failed: {e}");
                        self.connecting_deadline = None;
                        self.events.push_back(NetherHttpClientEvent::ConnectFailed);
                    }
                },
                JoinStep::Failed => {
                    self.connecting_deadline = None;
                    self.events.push_back(NetherHttpClientEvent::ConnectFailed);
                }
            }
        }

        if let Some(pool) = self.pool.as_mut() {
            let mut events = Vec::new();
            pool.drive(&mut events);

            for ((), event) in events {
                match event {
                    ConnectionEvent::Ready(addr) if !self.ready => {
                        self.ready = true;
                        self.remote_addr = addr;
                        self.connecting_deadline = None;
                        self.events.push_back(NetherHttpClientEvent::Connected);
                    }
                    ConnectionEvent::Ready(_) => {}
                    ConnectionEvent::Rtt(rtt) => self.rtt = Some(rtt),
                    ConnectionEvent::Message(Channel::Reliable, data) => {
                        self.received.push_back(data)
                    }
                    ConnectionEvent::Message(Channel::Unreliable, data) => {
                        self.received_unreliable.push_back(data)
                    }
                    ConnectionEvent::Failed => {
                        let was_ready = self.ready;
                        self.join = None;
                        self.pool = None;
                        self.connected = false;
                        self.connecting_deadline = None;
                        self.ready = false;
                        self.remote_addr = None;
                        self.rtt = None;
                        self.events.push_back(if was_ready {
                            NetherHttpClientEvent::Disconnected
                        } else {
                            NetherHttpClientEvent::ConnectFailed
                        });
                    }
                }
            }
        }

        if let Some(deadline) = self.connecting_deadline
            && now >= deadline
        {
            if self.pool.is_none() && self.attempts_left > 0 && self.begin_join().is_ok() {
                return;
            }
            let was_ready = self.ready;
            self.join = None;
            self.pool = None;
            self.connected = false;
            self.connecting_deadline = None;
            self.ready = false;
            self.remote_addr = None;
            self.rtt = None;
            self.events.push_back(if was_ready {
                NetherHttpClientEvent::Disconnected
            } else {
                NetherHttpClientEvent::ConnectFailed
            });
        }
    }
}

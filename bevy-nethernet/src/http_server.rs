use crate::connection::{ConnectionEvent, SessionPool};
use crate::http_wire;
use crate::server::NetherSessionId;
use crate::socket::bind_shared_socket;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use http::{Response, StatusCode};
use nethernet::connection::{Connection, IceMode};
use nethernet::prelude::{
    HttpSignaler, HttpSignalerConfig, HttpSignalerInput, HttpSignalerOutput, Offer, RejectReason,
    Sans, ServerData, ServerIdentity,
};
use nethernet::protocol::Signal;
use nethernet::protocol::webrtc::Description;
use nethernet::session::{Channel, Session};
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const MAX_ACCEPTS_PER_TICK: usize = 64;
const READ_CHUNK: usize = 4096;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct NetherHttpServerPlugin;

impl Plugin for NetherHttpServerPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherHttpServerEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherHttpServerSet)
                .run_if(resource_exists::<NetherHttpServer>),
        );
    }
}

impl NetherHttpServerPlugin {
    fn update(
        mut server: ResMut<NetherHttpServer>,
        mut events: MessageWriter<NetherHttpServerEvent>,
    ) {
        server.update();

        while let Some(event) = server.next_event() {
            events.write(event);
        }
    }
}

/// PreUpdate set containing NetherHttpServerPlugin's update system. Order your own
/// systems `.after(NetherHttpServerSet)` to see this tick's events/received data.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherHttpServerSet;

#[derive(Message, Clone, Debug)]
pub enum NetherHttpServerEvent {
    SessionConnected(NetherSessionId),
    SessionDisconnected(NetherSessionId),
}

struct TcpConn {
    stream: TcpStream,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    written: usize,
    close_after_write: bool,
    continued: bool,
    last_active: Instant,
}

impl TcpConn {
    fn refuse(&mut self, status: StatusCode) {
        let response = Response::builder()
            .status(status)
            .body(String::new())
            .expect("a status and an empty body are always a valid response");
        self.write_buf
            .extend_from_slice(&http_wire::encode_response(&response, false));
        self.close_after_write = true;
        self.read_buf.clear();
    }
}

struct SessionEntry {
    ready: bool,
    created: Instant,
}

#[derive(Resource)]
pub struct NetherHttpServer {
    listener: TcpListener,
    signaler: HttpSignaler,
    pool: SessionPool<NetherSessionId>,
    session_local_addr: SocketAddr,
    identity: Option<ServerIdentity>,
    idle_timeout: Duration,
    next_conn_id: u64,
    connections: HashMap<u64, TcpConn>,
    sessions: HashMap<NetherSessionId, SessionEntry>,
    received: VecDeque<(NetherSessionId, Box<[u8]>)>,
    received_unreliable: VecDeque<(NetherSessionId, Box<[u8]>)>,
    events: VecDeque<NetherHttpServerEvent>,
}

impl NetherHttpServer {
    pub fn bind<T>(bind_addr: SocketAddr, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut HttpSignalerConfig),
    {
        let mut config = HttpSignalerConfig::default();
        conf(&mut config);

        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;

        let (session_socket, session_local_addr) = bind_shared_socket()?;

        Ok(Self {
            listener,
            signaler: HttpSignaler::new(config),
            pool: SessionPool::new(session_socket),
            session_local_addr,
            identity: None,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            next_conn_id: 0,
            connections: HashMap::new(),
            sessions: HashMap::new(),
            received: VecDeque::new(),
            received_unreliable: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.idle_timeout = idle_timeout;
    }

    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    pub fn set_server_data(&mut self, data: ServerData) {
        let _ = self
            .signaler
            .handle(HttpSignalerInput::SetServerData(Box::new(data)));
    }

    pub fn sessions(&self) -> impl Iterator<Item = &NetherSessionId> {
        self.sessions
            .iter()
            .filter(|(_, entry)| entry.ready)
            .map(|(id, _)| id)
    }

    pub fn send(
        &mut self,
        id: &NetherSessionId,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        self.send_on(id, Channel::Reliable, data)
    }

    pub fn send_unreliable(
        &mut self,
        id: &NetherSessionId,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        self.send_on(id, Channel::Unreliable, data)
    }

    fn send_on(
        &mut self,
        id: &NetherSessionId,
        channel: Channel,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        if !self.sessions.contains_key(id) {
            return Err(nethernet::error::ProtocolError::Other(
                "unknown session".to_string(),
            ));
        }
        self.pool.send(id.clone(), channel, data.into());
        Ok(())
    }

    pub fn recv(&mut self) -> Option<(NetherSessionId, Box<[u8]>)> {
        self.received.pop_front()
    }

    pub fn recv_unreliable(&mut self) -> Option<(NetherSessionId, Box<[u8]>)> {
        self.received_unreliable.pop_front()
    }

    pub fn disconnect(&mut self, id: &NetherSessionId) {
        if self.sessions.remove(id).is_some() {
            self.pool.remove(id.clone());
            self.events
                .push_back(NetherHttpServerEvent::SessionDisconnected(id.clone()));
        }
    }

    pub fn next_event(&mut self) -> Option<NetherHttpServerEvent> {
        self.events.pop_front()
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        self.accept(now);
        self.pump_connections(now);

        let _ = self.signaler.handle(HttpSignalerInput::Update(now));

        while let Some(output) = self.signaler.poll() {
            self.handle_output(output, now);
        }

        self.drive_sessions();

        let idle_timeout = self.idle_timeout;
        let idle: Vec<u64> = self
            .connections
            .iter()
            .filter(|(_, conn)| now.saturating_duration_since(conn.last_active) >= idle_timeout)
            .map(|(&id, _)| id)
            .collect();
        for id in idle {
            self.connections.remove(&id);
            let _ = self.signaler.handle(HttpSignalerInput::Closed(id));
        }
        self.sessions.retain(|_, entry| {
            entry.ready || now.saturating_duration_since(entry.created) < CONNECT_TIMEOUT
        });
    }

    fn accept(&mut self, now: Instant) {
        for _ in 0..MAX_ACCEPTS_PER_TICK {
            let (stream, _addr) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            let Ok(peer) = stream.peer_addr() else {
                continue;
            };
            let _ = stream.set_nonblocking(true);

            let id = self.next_conn_id;
            self.next_conn_id += 1;

            self.connections.insert(
                id,
                TcpConn {
                    stream,
                    read_buf: Vec::new(),
                    write_buf: Vec::new(),
                    written: 0,
                    close_after_write: false,
                    continued: false,
                    last_active: now,
                },
            );
            let _ = self
                .signaler
                .handle(HttpSignalerInput::Connected(id, peer, now));
        }
    }

    fn pump_connections(&mut self, now: Instant) {
        let mut closed = Vec::new();
        let mut requests = Vec::new();

        for (&id, conn) in self.connections.iter_mut() {
            if conn.write_buf.is_empty() && conn.close_after_write {
                closed.push(id);
                continue;
            }

            if !conn.write_buf.is_empty() {
                match conn.stream.write(&conn.write_buf[conn.written..]) {
                    Ok(0) => {
                        closed.push(id);
                        continue;
                    }
                    Ok(n) => {
                        conn.written += n;
                        conn.last_active = now;
                        if conn.written == conn.write_buf.len() {
                            conn.write_buf.clear();
                            conn.written = 0;
                            if conn.close_after_write {
                                closed.push(id);
                                continue;
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => {
                        closed.push(id);
                        continue;
                    }
                }
            }

            let mut chunk = [0u8; READ_CHUNK];
            match conn.stream.read(&mut chunk) {
                Ok(0) => {
                    closed.push(id);
                    continue;
                }
                Ok(n) => {
                    conn.read_buf.extend_from_slice(&chunk[..n]);
                    conn.last_active = now;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => {
                    closed.push(id);
                    continue;
                }
            }

            loop {
                match http_wire::parse_request(&conn.read_buf) {
                    Ok(http_wire::Parsed::Complete(request, consumed)) => {
                        conn.read_buf.drain(..consumed);
                        conn.continued = false;
                        tracing::debug!(
                            "http request {} {} with {} headers",
                            request.method(),
                            request.uri(),
                            request.headers().len()
                        );
                        requests.push((id, *request));
                    }
                    Ok(http_wire::Parsed::Partial { .. })
                        if conn.read_buf.len() > http_wire::MAX_BODY =>
                    {
                        conn.refuse(StatusCode::PAYLOAD_TOO_LARGE);
                        break;
                    }
                    Ok(http_wire::Parsed::Partial { expects_continue }) => {
                        if expects_continue && !conn.continued {
                            conn.continued = true;
                            conn.write_buf
                                .extend_from_slice(http_wire::CONTINUE_RESPONSE);
                        }
                        break;
                    }
                    Err(error) => {
                        tracing::debug!("refusing an unreadable http request: {error:?}");
                        conn.refuse(match error {
                            http_wire::RequestError::TooManyHeaders => {
                                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                            }
                            http_wire::RequestError::Malformed => StatusCode::BAD_REQUEST,
                            http_wire::RequestError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                        });
                        break;
                    }
                }
            }
        }

        for (connection, request) in requests {
            let _ = self.signaler.handle(HttpSignalerInput::Request {
                connection,
                request: Box::new(request),
                proxied: None,
                now,
            });
        }

        for id in closed {
            self.connections.remove(&id);
            let _ = self.signaler.handle(HttpSignalerInput::Closed(id));
        }
    }

    fn handle_output(&mut self, output: HttpSignalerOutput, now: Instant) {
        match output {
            HttpSignalerOutput::Response {
                connection,
                response,
                keep_alive,
            } => {
                if let Some(conn) = self.connections.get_mut(&connection) {
                    conn.write_buf
                        .extend_from_slice(&http_wire::encode_response(&response, keep_alive));
                    conn.close_after_write = !keep_alive;
                }
            }
            HttpSignalerOutput::Close(connection) => {
                if let Some(conn) = self.connections.get_mut(&connection) {
                    conn.close_after_write = true;
                }
            }
            HttpSignalerOutput::Offer(offer) => self.handle_offer(*offer, now),
            HttpSignalerOutput::Wait(_) => {}
        }
    }

    fn handle_offer(&mut self, offer: Offer, now: Instant) {
        let accepted = accept_offer(&offer, self.session_local_addr, now).and_then(
            |(sdp, connection, ufrag)| match &self.identity {
                Some(identity) => identity
                    .augment(&sdp)
                    .map(|sdp| (sdp, connection, ufrag))
                    .map_err(|_| RejectReason::Unavailable),
                None => Ok((sdp, connection, ufrag)),
            },
        );
        match accepted {
            Ok((answer_sdp, connection, local_ufrag)) => {
                let _ = self.signaler.handle(HttpSignalerInput::Answer {
                    connection_id: offer.connection_id,
                    sdp: answer_sdp,
                });
                let id = NetherSessionId {
                    network_id: offer.network_id,
                    connection_id: offer.connection_id,
                };
                self.pool.add(id.clone(), connection, local_ufrag);
                self.sessions.insert(
                    id,
                    SessionEntry {
                        ready: false,
                        created: now,
                    },
                );
            }
            Err(reason) => {
                let _ = self.signaler.handle(HttpSignalerInput::Reject {
                    connection_id: offer.connection_id,
                    reason,
                });
            }
        }
    }

    fn drive_sessions(&mut self) {
        let mut events = Vec::new();
        self.pool.drive(&mut events);

        let mut failed = Vec::new();
        for (id, event) in events {
            let Some(entry) = self.sessions.get_mut(&id) else {
                continue;
            };
            match event {
                ConnectionEvent::Ready if !entry.ready => {
                    entry.ready = true;
                    self.events
                        .push_back(NetherHttpServerEvent::SessionConnected(id));
                }
                ConnectionEvent::Ready => {}
                ConnectionEvent::Message(Channel::Reliable, data) => {
                    self.received.push_back((id, data))
                }
                ConnectionEvent::Message(Channel::Unreliable, data) => {
                    self.received_unreliable.push_back((id, data))
                }
                ConnectionEvent::Failed => failed.push(id),
            }
        }

        for id in failed {
            self.disconnect(&id);
        }
    }
}

fn accept_offer(
    offer: &Offer,
    session_local_addr: SocketAddr,
    now: Instant,
) -> Result<(String, Connection, String), RejectReason> {
    let (remote_description, remote_candidates) =
        Description::parse(&offer.sdp).map_err(|_| RejectReason::Unavailable)?;
    let (session, description) =
        Session::new(session_local_addr, false, now).map_err(|_| RejectReason::Unavailable)?;
    let local_ufrag = description.ice.ufrag.clone();

    let offer_signal = Signal::offer(
        offer.connection_id,
        offer.sdp.clone(),
        offer.network_id.clone(),
    );
    let (connection, signals) = Connection::accept(
        session,
        description,
        &offer_signal,
        remote_description,
        remote_candidates,
        IceMode::Full,
        now,
    )
    .map_err(|_| RejectReason::Unavailable)?;

    let answer = signals
        .into_iter()
        .next()
        .ok_or(RejectReason::Unavailable)?;

    Ok((answer.data, connection, local_ufrag))
}

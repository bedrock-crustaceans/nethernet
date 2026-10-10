use crate::connection::{ConnectionEvent, SessionPool};
use crate::socket::{bind_discovery_socket, bind_shared_socket, send_discovery};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::IceMode;
use nethernet::prelude::{
    Answered, LanSignaler, LanSignalerConfig, LanSignalerInput, LanSignalerOutput, OfferPolicy,
    PlayerInfo, Sans, ServerData, ServerIdentity, TokenTrust,
};
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::Channel;
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_DATAGRAMS_PER_TICK: usize = 1024;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub struct NetherServerPlugin;

impl Plugin for NetherServerPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherServerEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherServerSet)
                .run_if(resource_exists::<NetherServer>),
        );
    }
}

impl NetherServerPlugin {
    fn update(mut server: ResMut<NetherServer>, mut events: MessageWriter<NetherServerEvent>) {
        server.update();

        while let Some(event) = server.next_event() {
            events.write(event);
        }
    }
}

/// PreUpdate set containing NetherServerPlugin's update system. Order your own
/// systems `.after(NetherServerSet)` to see this tick's events/received data.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherServerSet;

/// Unique within a [`NetherServer`], not globally: connection IDs are only unique
/// within the signaling network that issued them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetherSessionId {
    pub network_id: String,
    pub connection_id: u64,
}

#[derive(Message, Clone, Debug)]
pub enum NetherServerEvent {
    SessionConnected(NetherSessionId),
    SessionDisconnected(NetherSessionId),
}

struct SessionEntry {
    ready: bool,
    created: Instant,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    player: Option<Arc<PlayerInfo>>,
}

#[derive(Resource)]
pub struct NetherServer {
    signaler: LanSignaler,
    socket: UdpSocket,
    pool: SessionPool<NetherSessionId>,
    session_local_addr: SocketAddr,
    identity: Option<ServerIdentity>,
    token_trust: Option<TokenTrust>,
    infer_peer_candidates: bool,
    sessions: HashMap<NetherSessionId, SessionEntry>,
    received: VecDeque<(NetherSessionId, Box<[u8]>)>,
    received_unreliable: VecDeque<(NetherSessionId, Box<[u8]>)>,
    events: VecDeque<NetherServerEvent>,
    buf: Box<[u8]>,
}

impl NetherServer {
    pub fn new<T>(network_id: u64, bind_addr: SocketAddr, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut LanSignalerConfig),
    {
        let mut config = LanSignalerConfig::default();
        conf(&mut config);

        let socket = bind_discovery_socket(bind_addr)?;

        let (session_socket, session_local_addr) = bind_shared_socket()?;

        Ok(Self {
            signaler: LanSignaler::new(network_id, config),
            socket,
            pool: SessionPool::new(session_socket),
            session_local_addr,
            identity: None,
            token_trust: None,
            infer_peer_candidates: true,
            sessions: HashMap::new(),
            received: VecDeque::new(),
            received_unreliable: VecDeque::new(),
            events: VecDeque::new(),
            buf: vec![0u8; 2048].into_boxed_slice(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    pub fn set_token_trust(&mut self, token_trust: Option<TokenTrust>) {
        self.token_trust = token_trust;
    }

    pub fn set_infer_peer_candidates(&mut self, infer: bool) {
        self.infer_peer_candidates = infer;
    }

    pub fn set_server_data(&mut self, data: ServerData) {
        let _ = self
            .signaler
            .handle(LanSignalerInput::SetServerData(Box::new(data)));
    }

    pub fn sessions(&self) -> impl Iterator<Item = &NetherSessionId> {
        self.sessions
            .iter()
            .filter(|(_, entry)| entry.ready)
            .map(|(id, _)| id)
    }

    pub fn player(&self, id: &NetherSessionId) -> Option<Arc<PlayerInfo>> {
        self.sessions.get(id)?.player.clone()
    }

    pub fn rtt(&self, id: &NetherSessionId) -> Option<Duration> {
        self.sessions.get(id)?.rtt
    }

    pub fn remote_addr(&self, id: &NetherSessionId) -> Option<SocketAddr> {
        self.sessions.get(id)?.remote_addr
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
                .push_back(NetherServerEvent::SessionDisconnected(id.clone()));
        }
    }

    pub fn next_event(&mut self) -> Option<NetherServerEvent> {
        self.events.pop_front()
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match self.socket.recv_from(&mut self.buf) {
                Ok((len, addr)) => {
                    let _ = self.signaler.handle(LanSignalerInput::Datagram(
                        self.buf[..len].into(),
                        SocketAddr::new(addr.ip().to_canonical(), addr.port()),
                        now,
                    ));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                _ => break,
            }
        }

        let _ = self.signaler.handle(LanSignalerInput::Update(now));

        while let Some(output) = self.signaler.poll() {
            match output {
                LanSignalerOutput::Datagram(buf, addr) => {
                    let _ = send_discovery(&self.socket, &buf, addr);
                }
                LanSignalerOutput::Signal(signal) => self.handle_signal(signal, now),
                LanSignalerOutput::ServerDiscovered(..) | LanSignalerOutput::Wait(_) => {}
            }
        }

        let mut events = Vec::new();
        self.pool.drive(&mut events);

        let mut failed = Vec::new();
        for (id, event) in events {
            let Some(entry) = self.sessions.get_mut(&id) else {
                continue;
            };
            match event {
                ConnectionEvent::Ready(addr) if !entry.ready => {
                    entry.ready = true;
                    entry.remote_addr = addr;
                    self.events
                        .push_back(NetherServerEvent::SessionConnected(id));
                }
                ConnectionEvent::Ready(_) => {}
                ConnectionEvent::Rtt(rtt) => entry.rtt = Some(rtt),
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

        self.sessions.retain(|_, entry| {
            entry.ready || now.saturating_duration_since(entry.created) < CONNECT_TIMEOUT
        });
    }

    fn handle_signal(&mut self, signal: Signal, now: Instant) {
        if signal.signal_type == SignalType::Offer {
            self.handle_offer(signal, now);
            return;
        }

        let id = NetherSessionId {
            network_id: signal.network_id.clone(),
            connection_id: signal.connection_id,
        };
        if self.sessions.contains_key(&id) {
            self.pool.signal(id, &signal);
        }
    }

    fn handle_offer(&mut self, offer: Signal, now: Instant) {
        let id = NetherSessionId {
            network_id: offer.network_id.clone(),
            connection_id: offer.connection_id,
        };
        if self.sessions.contains_key(&id) {
            return;
        }

        let signaled_from = offer
            .network_id
            .parse()
            .ok()
            .and_then(|network_id| self.signaler.address(network_id));
        let mut policy = OfferPolicy::new(IceMode::Trickle)
            .with_inferred_peer_candidates(self.infer_peer_candidates);
        if let Some(identity) = &self.identity {
            policy = policy.with_identity(identity);
        }
        if let Some(trust) = &self.token_trust {
            policy = policy.with_token_trust(trust);
        }

        let answered = policy
            .admit(&offer, signaled_from, SystemTime::now())
            .and_then(|admitted| admitted.answer(self.session_local_addr, now));
        let Answered {
            connection,
            signals,
            local_ufrag,
            player,
            ..
        } = match answered {
            Ok(answered) => answered,
            Err(e) => {
                tracing::debug!("Refusing offer from {}: {}", offer.network_id, e);
                let signal = Signal::error(offer.connection_id, e.code(), offer.network_id);
                let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
                return;
            }
        };

        for signal in signals {
            let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
        }

        self.pool.add(id.clone(), connection, local_ufrag);
        self.sessions.insert(
            id,
            SessionEntry {
                ready: false,
                created: now,
                remote_addr: None,
                rtt: None,
                player: player.map(Arc::new),
            },
        );
    }
}

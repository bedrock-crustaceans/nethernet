use crate::connection::{ConnectionDriver, ConnectionEvent, bind_session_socket};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{Connection, IceMode};
use nethernet::prelude::{
    LanSignaler, LanSignalerConfig, LanSignalerInput, LanSignalerOutput, Sans, ServerData,
};
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::{Channel, Session};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

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
    driver: ConnectionDriver,
    ready: bool,
    created: Instant,
}

#[derive(Resource)]
pub struct NetherServer {
    signaler: LanSignaler,
    socket: UdpSocket,
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

        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;

        Ok(Self {
            signaler: LanSignaler::new(network_id, config),
            socket,
            sessions: HashMap::new(),
            received: VecDeque::new(),
            received_unreliable: VecDeque::new(),
            events: VecDeque::new(),
            buf: vec![0u8; 2048].into_boxed_slice(),
        })
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
        let Some(entry) = self.sessions.get_mut(id) else {
            return Err(nethernet::error::ProtocolError::Other(
                "unknown session".to_string(),
            ));
        };
        entry.driver.send(channel, data.into())
    }

    pub fn recv(&mut self) -> Option<(NetherSessionId, Box<[u8]>)> {
        self.received.pop_front()
    }

    pub fn recv_unreliable(&mut self) -> Option<(NetherSessionId, Box<[u8]>)> {
        self.received_unreliable.pop_front()
    }

    pub fn disconnect(&mut self, id: &NetherSessionId) {
        if self.sessions.remove(id).is_some() {
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
                        addr,
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
                    let _ = self.socket.send_to(&buf, addr);
                }
                LanSignalerOutput::Signal(signal) => self.handle_signal(signal, now),
                LanSignalerOutput::ServerDiscovered(..) | LanSignalerOutput::Wait(_) => {}
            }
        }

        let mut failed = Vec::new();
        for (id, entry) in self.sessions.iter_mut() {
            let mut events = Vec::new();
            entry.driver.drive(now, &mut events);

            for event in events {
                match event {
                    ConnectionEvent::Ready if !entry.ready => {
                        entry.ready = true;
                        self.events
                            .push_back(NetherServerEvent::SessionConnected(id.clone()));
                    }
                    ConnectionEvent::Ready => {}
                    ConnectionEvent::Message(Channel::Reliable, data) => {
                        self.received.push_back((id.clone(), data))
                    }
                    ConnectionEvent::Message(Channel::Unreliable, data) => {
                        self.received_unreliable.push_back((id.clone(), data))
                    }
                    ConnectionEvent::Failed => failed.push(id.clone()),
                }
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
        if let Some(entry) = self.sessions.get_mut(&id)
            && let Err(e) = entry.driver.handle_signal(&signal)
        {
            tracing::debug!("session rejected signal: {e}");
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

        let Ok((remote_description, remote_candidates)) = Connection::parse_offer(&offer) else {
            return;
        };
        let Ok((socket, local_addr)) = bind_session_socket() else {
            return;
        };
        let Ok((session, description)) = Session::new(local_addr, false) else {
            return;
        };
        let Ok((connection, signals)) = Connection::accept(
            session,
            description,
            &offer,
            remote_description,
            remote_candidates,
            IceMode::Trickle,
        ) else {
            return;
        };

        for signal in signals {
            let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
        }

        self.sessions.insert(
            id,
            SessionEntry {
                driver: ConnectionDriver::new(socket, connection),
                ready: false,
                created: now,
            },
        );
    }
}

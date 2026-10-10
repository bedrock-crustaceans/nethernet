use crate::connection::{ConnectionEvent, SessionPool};
use crate::socket::bind_shared_socket;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{Connection, IceMode, Timeouts};
use nethernet::prelude::{
    LanSignaler, LanSignalerConfig, LanSignalerInput, LanSignalerOutput, Sans, ServerData,
    ServerIdentity,
};
use nethernet::protocol::constants::LAN_DISCOVERY_PORT;
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::{Channel, Session};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_DATAGRAMS_PER_TICK: usize = 1024;
const DEFAULT_ATTEMPTS: u32 = 3;

pub struct NetherClientPlugin;

impl Plugin for NetherClientPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<NetherClientEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(NetherClientSet)
                .run_if(resource_exists::<NetherClient>),
        );
    }
}

impl NetherClientPlugin {
    fn update(mut client: ResMut<NetherClient>, mut events: MessageWriter<NetherClientEvent>) {
        client.update();

        while let Some(event) = client.next_event() {
            events.write(event);
        }
    }
}

#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetherClientSet;

#[derive(Message, Clone, Debug)]
pub enum NetherClientEvent {
    ServerDiscovered(u64, Box<ServerData>),
    Connected,
    Disconnected,
}

#[derive(Resource)]
pub struct NetherClient {
    signaler: LanSignaler,
    socket: UdpSocket,
    pool: SessionPool<()>,
    session_local_addr: SocketAddr,
    connected: bool,
    connecting_deadline: Option<Instant>,
    answered: bool,
    timeouts: Timeouts,
    attempts: u32,
    attempts_left: u32,
    target: u64,
    ready: bool,
    remote_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
    identity: Option<ServerIdentity>,
    received: VecDeque<Box<[u8]>>,
    received_unreliable: VecDeque<Box<[u8]>>,
    events: VecDeque<NetherClientEvent>,
    buf: Box<[u8]>,
}

impl NetherClient {
    pub fn new<T>(network_id: u64, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut LanSignalerConfig),
    {
        let mut config = LanSignalerConfig {
            broadcast_address: Some(SocketAddr::new(
                Ipv4Addr::BROADCAST.into(),
                LAN_DISCOVERY_PORT,
            )),
            ..LanSignalerConfig::default()
        };
        conf(&mut config);

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;

        let (session_socket, session_local_addr) = bind_shared_socket()?;

        Ok(Self {
            signaler: LanSignaler::new(network_id, config),
            socket,
            pool: SessionPool::new(session_socket),
            session_local_addr,
            connected: false,
            connecting_deadline: None,
            answered: false,
            timeouts: Timeouts::default(),
            attempts: DEFAULT_ATTEMPTS,
            attempts_left: 0,
            target: 0,
            ready: false,
            remote_addr: None,
            rtt: None,
            identity: None,
            received: VecDeque::new(),
            received_unreliable: VecDeque::new(),
            events: VecDeque::new(),
            buf: vec![0u8; 2048].into_boxed_slice(),
        })
    }

    pub fn discovered(&self) -> &HashMap<u64, ServerData> {
        self.signaler.discovered()
    }

    pub fn set_identity(&mut self, identity: ServerIdentity) {
        self.identity = Some(identity);
    }

    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    pub fn set_attempts(&mut self, attempts: u32) {
        self.attempts = attempts;
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

    pub fn connect(&mut self, target_network_id: u64) -> std::io::Result<()> {
        self.target = target_network_id;
        self.attempts_left = self.attempts.max(1);
        self.begin_attempt()
    }

    fn begin_attempt(&mut self) -> std::io::Result<()> {
        self.attempts_left = self.attempts_left.saturating_sub(1);
        let (session, description) = Session::new(self.session_local_addr, true, Instant::now())
            .map_err(std::io::Error::other)?;
        let local_ufrag = description.ice.ufrag.clone();

        let connection_id = rand::random::<u64>();
        let (connection, signals) = Connection::connect(
            session,
            description,
            connection_id,
            self.target.to_string(),
            IceMode::Trickle,
        );

        let now = Instant::now();
        for mut signal in signals {
            if let (Some(identity), SignalType::Offer) = (&self.identity, signal.signal_type) {
                signal.data = identity
                    .augment(&signal.data)
                    .map_err(std::io::Error::other)?;
            }
            let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
        }

        if self.connected {
            self.pool.remove(());
        }
        self.pool.add((), connection, local_ufrag);
        self.connected = true;
        self.connecting_deadline = Some(now + self.timeouts.negotiation);
        self.answered = false;
        self.ready = false;
        self.remote_addr = None;
        self.rtt = None;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.connecting_deadline = None;
        if self.connected {
            self.pool.remove(());
            self.connected = false;
        }
        if self.ready {
            self.ready = false;
            self.remote_addr = None;
            self.rtt = None;
            self.events.push_back(NetherClientEvent::Disconnected);
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), nethernet::error::ProtocolError> {
        self.send_on(Channel::Reliable, data)
    }

    pub fn send_unreliable(&mut self, data: &[u8]) -> Result<(), nethernet::error::ProtocolError> {
        self.send_on(Channel::Unreliable, data)
    }

    fn send_on(
        &mut self,
        channel: Channel,
        data: &[u8],
    ) -> Result<(), nethernet::error::ProtocolError> {
        if !self.connected {
            return Err(nethernet::error::ProtocolError::Other(
                "not connected".to_string(),
            ));
        }
        self.pool.send((), channel, data.into());
        Ok(())
    }

    pub fn recv(&mut self) -> Option<Box<[u8]>> {
        self.received.pop_front()
    }

    pub fn recv_unreliable(&mut self) -> Option<Box<[u8]>> {
        self.received_unreliable.pop_front()
    }

    pub fn next_event(&mut self) -> Option<NetherClientEvent> {
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
                LanSignalerOutput::ServerDiscovered(id, data) => self
                    .events
                    .push_back(NetherClientEvent::ServerDiscovered(id, data)),
                LanSignalerOutput::Signal(signal) => self.handle_signal(signal, now),
                LanSignalerOutput::Wait(_) => {}
            }
        }

        if !self.connected {
            return;
        }

        let mut events = Vec::new();
        self.pool.drive(&mut events);

        for ((), event) in events {
            match event {
                ConnectionEvent::Ready(addr) if !self.ready => {
                    self.ready = true;
                    self.remote_addr = addr;
                    self.connecting_deadline = None;
                    self.events.push_back(NetherClientEvent::Connected);
                }
                ConnectionEvent::Ready(_) => {}
                ConnectionEvent::Rtt(rtt) => self.rtt = Some(rtt),
                ConnectionEvent::Message(Channel::Reliable, data) => self.received.push_back(data),
                ConnectionEvent::Message(Channel::Unreliable, data) => {
                    self.received_unreliable.push_back(data)
                }
                ConnectionEvent::Failed => {
                    self.connecting_deadline = None;
                    self.connected = false;
                    self.events.push_back(NetherClientEvent::Disconnected);
                }
            }
        }

        if let Some(deadline) = self.connecting_deadline
            && now >= deadline
        {
            if !self.answered && self.attempts_left > 0 && self.begin_attempt().is_ok() {
                return;
            }
            self.connecting_deadline = None;
            self.pool.remove(());
            self.connected = false;
            self.events.push_back(NetherClientEvent::Disconnected);
        }
    }

    fn handle_signal(&mut self, signal: Signal, now: Instant) {
        if signal.signal_type == SignalType::Offer || !self.connected {
            return;
        }
        if signal.signal_type == SignalType::Answer
            && !self.answered
            && self.connecting_deadline.is_some()
        {
            self.answered = true;
            self.connecting_deadline = Some(now + self.timeouts.establish());
        }
        self.pool.signal((), &signal);
    }
}

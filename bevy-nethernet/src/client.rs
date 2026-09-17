use crate::connection::{ConnectionDriver, ConnectionEvent, bind_session_socket};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use nethernet::connection::{Connection, IceMode};
use nethernet::prelude::{
    LanSignaler, LanSignalerConfig, LanSignalerInput, LanSignalerOutput, Sans, ServerData,
};
use nethernet::protocol::constants::LAN_DISCOVERY_PORT;
use nethernet::protocol::{Signal, SignalType};
use nethernet::session::{Channel, Session};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Instant;

const MAX_DATAGRAMS_PER_TICK: usize = 1024;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

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

/// PreUpdate set containing NetherClientPlugin's update system. Order your own
/// systems `.after(NetherClientSet)` to see this tick's events/received data.
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
    connection: Option<ConnectionDriver>,
    connecting_since: Option<Instant>,
    ready: bool,
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

        Ok(Self {
            signaler: LanSignaler::new(network_id, config),
            socket,
            connection: None,
            connecting_since: None,
            ready: false,
            received: VecDeque::new(),
            received_unreliable: VecDeque::new(),
            events: VecDeque::new(),
            buf: vec![0u8; 2048].into_boxed_slice(),
        })
    }

    pub fn discovered(&self) -> &HashMap<u64, ServerData> {
        self.signaler.discovered()
    }

    pub fn is_connected(&self) -> bool {
        self.ready
    }

    pub fn connect(&mut self, target_network_id: u64) -> std::io::Result<()> {
        let (socket, local_addr) = bind_session_socket()?;
        let (session, description) =
            Session::new(local_addr, true).map_err(std::io::Error::other)?;

        let connection_id = rand::random::<u64>();
        let (connection, signals) = Connection::connect(
            session,
            description,
            connection_id,
            target_network_id.to_string(),
            IceMode::Trickle,
        );

        let now = Instant::now();
        for signal in signals {
            let _ = self.signaler.handle(LanSignalerInput::Signal(signal, now));
        }

        self.connection = Some(ConnectionDriver::new(socket, connection));
        self.connecting_since = Some(now);
        self.ready = false;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.connecting_since = None;
        self.connection = None;
        if self.ready {
            self.ready = false;
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
        let Some(connection) = self.connection.as_mut() else {
            return Err(nethernet::error::ProtocolError::Other(
                "not connected".to_string(),
            ));
        };
        connection.send(channel, data.into())
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
                LanSignalerOutput::Signal(signal) => self.handle_signal(signal),
                LanSignalerOutput::Wait(_) => {}
            }
        }

        let Some(connection) = self.connection.as_mut() else {
            return;
        };

        let mut events = Vec::new();
        connection.drive(now, &mut events);

        for event in events {
            match event {
                ConnectionEvent::Ready if !self.ready => {
                    self.ready = true;
                    self.connecting_since = None;
                    self.events.push_back(NetherClientEvent::Connected);
                }
                ConnectionEvent::Ready => {}
                ConnectionEvent::Message(Channel::Reliable, data) => self.received.push_back(data),
                ConnectionEvent::Message(Channel::Unreliable, data) => {
                    self.received_unreliable.push_back(data)
                }
                ConnectionEvent::Failed => {
                    self.connecting_since = None;
                    self.connection = None;
                    self.events.push_back(NetherClientEvent::Disconnected);
                }
            }
        }

        if let Some(since) = self.connecting_since
            && now.saturating_duration_since(since) >= CONNECT_TIMEOUT
        {
            self.connecting_since = None;
            self.connection = None;
            self.events.push_back(NetherClientEvent::Disconnected);
        }
    }

    fn handle_signal(&mut self, signal: Signal) {
        if signal.signal_type == SignalType::Offer {
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        if let Err(e) = connection.handle_signal(&signal) {
            tracing::debug!("connection rejected signal: {e}");
            self.disconnect();
        }
    }
}

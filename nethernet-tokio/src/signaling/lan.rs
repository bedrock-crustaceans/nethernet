//! Signaling over LAN discovery, driven on top of the sans-IO state machine.

use crate::addr::Addr;
use crate::error::{NethernetError, Result};
use crate::protocol::Signal;
use crate::signaling::Signaling;
use futures::Stream;
use nethernet::prelude::{
    LanSignaler, LanSignalerInput, LanSignalerOutput, RequestPacket, Sans, ServerData,
};
use nethernet::protocol::packet::discovery::marshal;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use nethernet::signaling::lan::config::LanSignalerConfig as LanConfig;

/// Largest datagram a discovery packet is read into.
const BUFFER_SIZE: usize = 4096;

/// Longest a driver sleeps when the state machine asks for nothing sooner.
const MAX_IDLE: Duration = Duration::from_secs(1);

enum Command {
    Signal(Box<Signal>, oneshot::Sender<Result<()>>),
    SetServerData(Box<ServerData>),
}

/// A snapshot of the state the driver keeps, so callers can read it without stopping the
/// state machine to ask.
#[derive(Default)]
struct Shared {
    addresses: RwLock<HashMap<u64, SocketAddr>>,
    discovered: RwLock<HashMap<u64, ServerData>>,
}

/// LAN discovery signaling for a single NetherNet network.
pub struct LanSignaling {
    network_id: u64,
    commands: mpsc::UnboundedSender<Command>,
    signal_tx: broadcast::Sender<Signal>,
    shared: Arc<Shared>,
    cancel_token: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl LanSignaling {
    /// Binds a discovery socket and starts the signaling on it.
    pub async fn new(network_id: u64, bind_addr: SocketAddr) -> Result<Self> {
        Self::with_config(network_id, bind_addr, LanConfig::default()).await
    }

    /// Binds a discovery socket and starts the signaling using the given options.
    ///
    /// A socket bound to the discovery port answers the requests of other networks rather
    /// than broadcasting its own, unless the configuration names an address to broadcast
    /// to itself.
    pub async fn with_config(
        network_id: u64,
        bind_addr: SocketAddr,
        mut config: LanConfig,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.set_broadcast(true)?;

        if config.broadcast_address.is_none() && bind_addr.port() != config.discovery_port {
            config.broadcast_address = Some(SocketAddr::new(
                Ipv4Addr::BROADCAST.into(),
                config.discovery_port,
            ));
        }

        let (signal_tx, _) = broadcast::channel(100);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        let cancel_token = CancellationToken::new();

        let task = Self::drive(
            LanSignaler::new(network_id, config),
            Arc::new(socket),
            command_rx,
            signal_tx.clone(),
            shared.clone(),
            cancel_token.clone(),
        );

        Ok(Self {
            network_id,
            commands,
            signal_tx,
            shared,
            cancel_token,
            task: Some(task),
        })
    }

    /// Stops the signaling and waits for its driver to finish.
    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Sets the data advertised in response to discovery requests.
    pub fn set_server_data(&self, server_data: ServerData) {
        let _ = self
            .commands
            .send(Command::SetServerData(Box::new(server_data)));
    }

    /// The servers that have answered a discovery request, keyed by their network ID.
    pub async fn discover(&self) -> HashMap<u64, ServerData> {
        self.shared
            .discovered
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The address a remote network was last seen at.
    pub async fn get_address(&self, network_id: u64) -> Option<SocketAddr> {
        self.shared
            .addresses
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&network_id)
            .copied()
    }

    fn drive(
        mut signaler: LanSignaler,
        socket: Arc<UdpSocket>,
        mut commands: mpsc::UnboundedReceiver<Command>,
        signal_tx: broadcast::Sender<Signal>,
        shared: Arc<Shared>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; BUFFER_SIZE];
            let mut wake = Instant::now();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    received = socket.recv_from(&mut buf) => match received {
                        Ok((len, addr)) => {
                            let input = LanSignalerInput::Datagram(
                                buf[..len].into(),
                                addr,
                                Instant::now(),
                            );
                            if let Err(e) = signaler.handle(input) {
                                tracing::debug!("Failed to handle datagram from {}: {}", addr, e);
                            }
                        }
                        Err(e) => tracing::debug!("Socket receive error: {}", e),
                    },
                    command = commands.recv() => match command {
                        Some(Command::Signal(signal, reply)) => {
                            let result = signaler
                                .handle(LanSignalerInput::Signal(*signal, Instant::now()))
                                .map_err(|e| NethernetError::Other(e.to_string()));
                            let _ = reply.send(result);
                        }
                        Some(Command::SetServerData(data)) => {
                            let _ = signaler.handle(LanSignalerInput::SetServerData(data));
                        }
                        None => break,
                    },
                    _ = tokio::time::sleep_until(wake.into()) => {
                        let _ = signaler.handle(LanSignalerInput::Update(Instant::now()));
                    }
                }

                while let Some(output) = signaler.poll() {
                    match output {
                        LanSignalerOutput::Datagram(buf, addr) => {
                            if let Err(e) = socket.send_to(&buf, addr).await {
                                tracing::debug!("Failed to send to {}: {}", addr, e);
                            }
                        }
                        LanSignalerOutput::Signal(signal) => {
                            let _ = signal_tx.send(signal);
                        }
                        LanSignalerOutput::ServerDiscovered(network_id, data) => {
                            shared
                                .discovered
                                .write()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(network_id, *data);
                        }
                        LanSignalerOutput::Wait(wait) => {
                            wake = Instant::now() + wait.min(MAX_IDLE);
                        }
                    }
                }

                *shared
                    .addresses
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = signaler.addresses().collect();
            }
        })
    }
}

impl Drop for LanSignaling {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Signaling for LanSignaling {
    async fn signal(&self, signal: Signal) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Signal(Box::new(signal), reply_tx))
            .map_err(|_| NethernetError::ConnectionClosed)?;

        reply_rx
            .await
            .map_err(|_| NethernetError::ConnectionClosed)?
    }

    fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    fn network_id(&self) -> String {
        self.network_id.to_string()
    }

    fn remote_address(&self, addr: &Addr) -> Option<SocketAddr> {
        let network_id = addr.network_id.parse::<u64>().ok()?;
        self.shared
            .addresses
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&network_id)
            .copied()
    }

    fn set_pong_data(&self, data: &[u8]) {
        match ServerData::from_pong_data(data) {
            Ok(server_data) => self.set_server_data(server_data),
            Err(e) => tracing::error!("Failed to parse pong data: {}", e),
        }
    }
}

/// Broadcasts a single discovery request from a socket of its own, for callers that only
/// want to find the servers on their network.
///
/// The socket is bound to an ephemeral port, so it is never mistaken for a server.
pub async fn scan(network_id: u64, port: u16, timeout: Duration) -> Result<HashMap<u64, ServerData>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let request = marshal(&RequestPacket, network_id)?;
    socket
        .send_to(
            &request,
            SocketAddr::new(Ipv4Addr::BROADCAST.into(), port),
        )
        .await?;

    let mut signaler = LanSignaler::new(network_id, LanConfig::default());
    let mut found = HashMap::new();
    let mut buf = vec![0u8; BUFFER_SIZE];
    let deadline = tokio::time::Instant::now() + timeout;

    while let Ok(Ok((len, addr))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
    {
        let input = LanSignalerInput::Datagram(buf[..len].into(), addr, Instant::now());
        if signaler.handle(input).is_err() {
            continue;
        }

        while let Some(output) = signaler.poll() {
            if let LanSignalerOutput::ServerDiscovered(network_id, data) = output {
                found.insert(network_id, *data);
            }
        }
    }

    Ok(found)
}

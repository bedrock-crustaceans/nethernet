//! LAN discovery and signaling over encrypted UDP datagrams.
use crate::addr::Addr;
use crate::error::{NetherError, Result};
use crate::protocol::Signal;
use futures::Stream;
use nethernet::prelude::{
    LanSignaler, LanSignalerInput, LanSignalerOutput, Packets, RequestPacket, Sans, ServerData,
};
use nethernet::protocol::packet::discovery::encode;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use nethernet::signaling::lan::config::LanSignalerConfig as LanConfig;

const BUFFER_SIZE: usize = 4096;

const MAX_IDLE: Duration = Duration::from_secs(1);

enum Command {
    Signal(Box<Signal>, oneshot::Sender<Result<()>>),
    SetServerData(Box<ServerData>),
    Discovered(oneshot::Sender<HashMap<u64, ServerData>>),
    Address(u64, oneshot::Sender<Option<SocketAddr>>),
}

/// Answers discovery requests and carries offers, answers and candidates as signals.
pub struct LanSignaling {
    network_id: u64,
    commands: mpsc::UnboundedSender<Command>,
    signal_tx: broadcast::Sender<Signal>,
    cancel_token: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl LanSignaling {
    /// The network id is this peer's id and bind_addr is the discovery socket.
    pub async fn new(network_id: u64, bind_addr: SocketAddr) -> Result<Self> {
        Self::with_config(network_id, bind_addr, LanConfig::default()).await
    }

    /// Broadcasts to 255.255.255.255 on the discovery port unless the bind port equals it or a broadcast address is set.
    pub async fn with_config(
        network_id: u64,
        bind_addr: SocketAddr,
        mut config: LanConfig,
    ) -> Result<Self> {
        let socket = bind_discovery_socket(bind_addr)?;

        if config.broadcast_address.is_none() && bind_addr.port() != config.discovery_port {
            config.broadcast_address = Some(SocketAddr::new(
                Ipv4Addr::BROADCAST.into(),
                config.discovery_port,
            ));
        }

        let (signal_tx, _) = broadcast::channel(100);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();

        let task = Self::drive(
            LanSignaler::new(network_id, config),
            Arc::new(socket),
            command_rx,
            signal_tx.clone(),
            cancel_token.clone(),
        );

        Ok(Self {
            network_id,
            commands,
            signal_tx,
            cancel_token,
            task: Some(task),
        })
    }

    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    pub fn set_server_data(&self, server_data: ServerData) {
        let _ = self
            .commands
            .send(Command::SetServerData(Box::new(server_data)));
    }

    /// Servers that have answered discovery so far, by network id.
    pub async fn discover(&self) -> HashMap<u64, ServerData> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.commands.send(Command::Discovered(reply_tx)).is_err() {
            return HashMap::new();
        }
        reply_rx.await.unwrap_or_default()
    }

    /// Source address of a discovered server.
    pub async fn get_address(&self, network_id: u64) -> Option<SocketAddr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Address(network_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    pub async fn signal(&self, signal: Signal) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Signal(Box::new(signal), reply_tx))
            .map_err(|_| NetherError::ConnectionClosed)?;

        reply_rx.await.map_err(|_| NetherError::ConnectionClosed)?
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
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

    pub fn network_id(&self) -> String {
        self.network_id.to_string()
    }

    pub fn disable_trickle_ice(&self) -> bool {
        false
    }

    pub async fn remote_address(&self, addr: &Addr) -> Option<SocketAddr> {
        let network_id = addr.network_id.parse::<u64>().ok()?;
        self.get_address(network_id).await
    }

    pub fn set_pong_data(&self, data: &[u8]) {
        match ServerData::from_pong_data(data) {
            Ok(server_data) => self.set_server_data(server_data),
            Err(e) => tracing::error!("Failed to parse pong data: {}", e),
        }
    }

    fn drive(
        mut signaler: LanSignaler,
        socket: Arc<UdpSocket>,
        mut commands: mpsc::UnboundedReceiver<Command>,
        signal_tx: broadcast::Sender<Signal>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; BUFFER_SIZE];
            let mut wake = Instant::now();
            let mut discovered: HashMap<u64, ServerData> = HashMap::new();
            let mut addresses: HashMap<u64, SocketAddr> = HashMap::new();
            let dual_stack = socket.local_addr().is_ok_and(|addr| addr.is_ipv6());

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    received = socket.recv_from(&mut buf) => match received {
                        Ok((len, addr)) => {
                            let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
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
                                .map_err(|e| NetherError::Other(e.to_string()));
                            let _ = reply.send(result);
                        }
                        Some(Command::SetServerData(data)) => {
                            let _ = signaler.handle(LanSignalerInput::SetServerData(data));
                        }
                        Some(Command::Discovered(reply)) => {
                            let _ = reply.send(discovered.clone());
                        }
                        Some(Command::Address(network_id, reply)) => {
                            let _ = reply.send(addresses.get(&network_id).copied());
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
                            if let Err(e) =
                                socket.send_to(&buf, socket_family(addr, dual_stack)).await
                            {
                                tracing::debug!("Failed to send to {}: {}", addr, e);
                            }
                        }
                        LanSignalerOutput::Signal(signal) => {
                            let _ = signal_tx.send(signal);
                        }
                        LanSignalerOutput::ServerDiscovered(network_id, data) => {
                            discovered.insert(network_id, *data);
                        }
                        LanSignalerOutput::Wait(wait) => {
                            wake = Instant::now() + wait.min(MAX_IDLE);
                        }
                    }
                }

                addresses = signaler.addresses().collect();
            }
        })
    }
}

fn bind_discovery_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => bind_dual_stack(addr)?,
        _ => std::net::UdpSocket::bind(addr)?,
    };
    socket.set_nonblocking(true)?;
    socket.set_broadcast(true)?;
    UdpSocket::from_std(socket)
}

fn bind_dual_stack(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) else {
        return std::net::UdpSocket::bind(addr);
    };
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), addr.port()).into())?;
    Ok(socket.into())
}

fn socket_family(addr: SocketAddr, dual_stack: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if dual_stack => {
            SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
        }
        _ => addr,
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

/// Broadcasts one discovery request to the port and collects responses until the timeout elapses.
pub async fn scan(
    network_id: u64,
    port: u16,
    timeout: Duration,
) -> Result<HashMap<u64, ServerData>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let request = encode(&Packets::Request(RequestPacket), network_id)?;
    socket
        .send_to(&request, SocketAddr::new(Ipv4Addr::BROADCAST.into(), port))
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

//! Drives a sans-IO [`nethernet::connection::Connection`] over a real UDP socket.
//!
//! NetherNet's actual WebRTC session (ICE, DTLS, SCTP, DCEP) is implemented directly on
//! top of the `rtc` crate in the sans-IO `nethernet` crate; this module is the Tokio
//! glue that feeds it datagrams and timers from a real socket, in a background task, and
//! exposes the async `send`/`recv` surface the rest of this crate is built on.

use crate::addr::Addr;
use crate::error::{NethernetError, Result};
use bytes::Bytes;
use nethernet::connection::Connection as SansConnection;
use nethernet::identity::PlayerInfo;
use nethernet::protocol::Signal;
pub use nethernet::session::Channel;
use nethernet::session::{SessionEvent, SessionOutput};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Longest the driver sleeps when the connection asks for nothing sooner.
const MAX_IDLE: Duration = Duration::from_secs(1);

/// Default capacity for the bounded packet channels of a session.
const PACKET_CHANNEL_CAPACITY: usize = 1024;

pub(crate) enum Command {
    Send(Channel, Bytes),
    Signal(Signal),
}

/// A single NetherNet session: a [`SansConnection`] driven over a real UDP socket in a
/// background task.
pub struct Session {
    local_addr: Addr,
    remote_addr: Arc<RwLock<Addr>>,
    command_tx: mpsc::UnboundedSender<Command>,
    packet_rx: Mutex<mpsc::Receiver<Bytes>>,
    unreliable_rx: Mutex<mpsc::Receiver<Bytes>>,
    closed: Arc<RwLock<bool>>,
    close_token: CancellationToken,
    player: Arc<RwLock<Option<Arc<PlayerInfo>>>>,
    task: JoinHandle<()>,
}

impl Session {
    /// Spawns the background driver for an already-negotiated-enough [`SansConnection`]
    /// (the initial offer/answer and, for trickle ICE, the first candidate should already
    /// be applied - see [`crate::transport::listener`]/[`crate::transport::stream`]), and
    /// returns the session along with a receiver that resolves once both data channels
    /// are open (mirroring the old behavior of not handing back a session until it is
    /// actually usable).
    pub(crate) fn spawn(
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
    ) -> (Self, oneshot::Receiver<()>) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);
        let (unreliable_tx, unreliable_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();

        let remote_addr = Arc::new(RwLock::new(remote));
        let closed = Arc::new(RwLock::new(false));
        let close_token = CancellationToken::new();

        let task = Self::drive(
            socket,
            connection,
            command_rx,
            packet_tx,
            unreliable_tx,
            Some(ready_tx),
            remote_addr.clone(),
            closed.clone(),
            close_token.clone(),
        );

        (
            Self {
                local_addr: local,
                remote_addr,
                command_tx,
                packet_rx: Mutex::new(packet_rx),
                unreliable_rx: Mutex::new(unreliable_rx),
                closed,
                close_token,
                player: Arc::new(RwLock::new(None)),
                task,
            },
            ready_rx,
        )
    }

    /// A sender that forwards further signals (e.g. a late-trickled or redundant
    /// candidate) into the running connection.
    pub(crate) fn signal_sender(&self) -> mpsc::UnboundedSender<Command> {
        self.command_tx.clone()
    }

    #[allow(clippy::too_many_arguments)]
    fn drive(
        socket: Arc<UdpSocket>,
        mut connection: SansConnection,
        mut commands: mpsc::UnboundedReceiver<Command>,
        packet_tx: mpsc::Sender<Bytes>,
        unreliable_tx: mpsc::Sender<Bytes>,
        mut ready_tx: Option<oneshot::Sender<()>>,
        remote_addr: Arc<RwLock<Addr>>,
        closed: Arc<RwLock<bool>>,
        close_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut wake = Instant::now() + MAX_IDLE;

            loop {
                tokio::select! {
                    biased;

                    _ = close_token.cancelled() => break,
                    received = socket.recv_from(&mut buf) => match received {
                        Ok((n, from)) => {
                            let now = Instant::now();
                            if let Err(e) = connection.handle_packet(&buf[..n], from, now) {
                                tracing::debug!("packet handling error: {e}");
                            }
                        }
                        Err(e) => tracing::debug!("recv error: {e}"),
                    },
                    command = commands.recv() => match command {
                        Some(Command::Send(channel, data)) => {
                            if let Err(e) = connection.send(channel, data) {
                                tracing::debug!("send error: {e}");
                            }
                        }
                        Some(Command::Signal(signal)) => {
                            if let Err(e) = connection.handle_signal(&signal) {
                                tracing::debug!("signal handling error: {e}");
                            }
                        }
                        None => break,
                    },
                    _ = tokio::time::sleep_until(wake.into()) => {
                        let now = Instant::now();
                        if let Err(e) = connection.handle_timeout(now) {
                            tracing::debug!("timeout handling error: {e}");
                        }
                    }
                }

                while let Some(output) = connection.poll() {
                    match output {
                        SessionOutput::Send(data, to) => {
                            if let Err(e) = socket.send_to(&data, to).await {
                                tracing::debug!("send_to error: {e}");
                            }
                        }
                        SessionOutput::Event(SessionEvent::Ready) => {
                            if let Some(addr) = connection.remote_addr() {
                                remote_addr.write().await.socket_addr = Some(addr);
                            }
                            if let Some(tx) = ready_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                        SessionOutput::Message(Channel::Reliable, data) => {
                            if packet_tx.send(Bytes::from(data)).await.is_err() {
                                break;
                            }
                        }
                        SessionOutput::Message(Channel::Unreliable, data) => {
                            let _ = unreliable_tx.try_send(Bytes::from(data));
                        }
                    }
                }

                let now = Instant::now();
                wake = connection.poll_timeout(now).unwrap_or(now + MAX_IDLE);
            }

            *closed.write().await = true;
            close_token.cancel();
        })
    }

    /// Sends data over the session using the reliable data channel, splitting the
    /// payload into protocol segments as needed.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        if *self.closed.read().await {
            return Err(NethernetError::ConnectionClosed);
        }
        self.command_tx
            .send(Command::Send(Channel::Reliable, data))
            .map_err(|_| NethernetError::ConnectionClosed)
    }

    /// Sends data over the session using the unreliable data channel.
    ///
    /// Data sent over a channel that was opened out of band is dropped by remote
    /// connections that did not open the matching channel themselves.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        if *self.closed.read().await {
            return Err(NethernetError::ConnectionClosed);
        }
        self.command_tx
            .send(Command::Send(Channel::Unreliable, data))
            .map_err(|_| NethernetError::ConnectionClosed)
    }

    /// Receives the next complete packet from the session.
    ///
    /// Returns `Ok(None)` once the session has been closed.
    pub async fn recv(&self) -> Result<Option<Bytes>> {
        if *self.closed.read().await {
            return Ok(None);
        }
        Ok(self.packet_rx.lock().await.recv().await)
    }

    /// Receives the next complete packet from the unreliable data channel.
    ///
    /// Returns `Ok(None)` once the session has been closed.
    pub async fn recv_unreliable(&self) -> Result<Option<Bytes>> {
        if *self.closed.read().await {
            return Ok(None);
        }
        Ok(self.unreliable_rx.lock().await.recv().await)
    }

    /// Shuts down the session by marking it closed and stopping its background driver.
    ///
    /// After this call the session is considered closed; calling `close` again is a
    /// no-op.
    pub async fn close(&self) -> Result<()> {
        let mut closed = self.closed.write().await;
        if *closed {
            return Ok(());
        }
        *closed = true;
        self.close_token.cancel();
        Ok(())
    }

    /// Returns the local address of the session.
    pub async fn local_addr(&self) -> Addr {
        self.local_addr.clone()
    }

    /// Returns the address of the remote connection, once known.
    pub async fn remote_addr(&self) -> Addr {
        self.remote_addr.read().await.clone()
    }

    /// Records the identity the connection was accepted with.
    pub async fn set_player(&self, player: Arc<PlayerInfo>) {
        *self.player.write().await = Some(player);
    }

    /// The identity the connection was accepted with, or [`None`] when identities are not
    /// validated or the connection was dialed rather than accepted.
    ///
    /// Everything it claims is only as trustworthy as the policy the offer was validated
    /// with, and only its public key is bound to a key the peer had to hold.
    pub async fn player(&self) -> Option<Arc<PlayerInfo>> {
        self.player.read().await.clone()
    }

    /// Resolves once the session has been closed.
    pub async fn closed(&self) {
        self.close_token.cancelled().await
    }

    /// Reports whether the session has been closed.
    pub async fn is_closed(&self) -> bool {
        *self.closed.read().await
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close_token.cancel();
        self.task.abort();
    }
}

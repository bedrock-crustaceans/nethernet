//! Drives a sans-IO [`nethernet::connection::Connection`] over a real UDP socket.
//!
//! NetherNet's actual WebRTC session (ICE, DTLS, SCTP, DCEP) is implemented directly on
//! top of the `rtc` crate in the sans-IO `nethernet` crate; this module is the Tokio
//! glue that feeds it datagrams and timers from a real socket, in a background task, and
//! exposes the async `send`/`recv` surface the rest of this crate is built on.
//!
//! All mutable state lives only inside that task; callers reach it through a [`Command`]
//! channel instead of a lock. Receiving is split out into [`SessionReceiver`], since each
//! channel only ever has one legitimate reader, while [`Session`] itself is cheap to
//! clone and hand to every task that needs to send or query it.

pub(crate) mod command;

pub(crate) use command::Command;

use crate::addr::Addr;
use crate::error::{NethernetError, Result};
use bytes::Bytes;
use nethernet::connection::Connection as SansConnection;
use nethernet::identity::PlayerInfo;
pub use nethernet::session::Channel;
use nethernet::session::{SessionEvent, SessionOutput};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Longest the driver sleeps when the connection asks for nothing sooner.
const MAX_IDLE: Duration = Duration::from_secs(1);

/// Default capacity for the bounded packet channels of a session.
const PACKET_CHANNEL_CAPACITY: usize = 1024;

/// Aborts the driver task once nothing references it anymore.
struct TaskGuard {
    close_token: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.close_token.cancel();
        self.task.abort();
    }
}

/// A cheaply-cloneable handle to a NetherNet session: a [`SansConnection`] driven over a
/// real UDP socket in a background task.
///
/// Cloning it does not spawn anything new; every clone talks to the same background
/// task, which is aborted once every clone and every [`SessionReceiver`] of it are
/// dropped.
#[derive(Clone)]
pub struct Session {
    local_addr: Addr,
    /// The remote's identity (network and connection ID); its `socket_addr` is always
    /// `None` here and read from the driver task instead, since it is the only part
    /// learned after the session starts.
    remote_addr: Addr,
    command_tx: mpsc::UnboundedSender<Command>,
    close_token: CancellationToken,
    _guard: Arc<TaskGuard>,
}

/// The receiving half of one of a session's data channels.
///
/// Not `Clone`: only one place should ever pull the "next" message off a channel. Holds
/// its own clone of the driver's guard, so dropping every [`Session`] handle doesn't cut
/// off a receiver still in use elsewhere.
pub struct SessionReceiver {
    rx: mpsc::Receiver<Bytes>,
    _guard: Arc<TaskGuard>,
}

impl SessionReceiver {
    /// Receives the next complete packet from the channel.
    ///
    /// Returns `Ok(None)` once the session has been closed.
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        Ok(self.rx.recv().await)
    }

    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.rx.poll_recv(cx)
    }
}

/// A session handed back once it is usable, alongside the exclusive receivers of its two
/// data channels.
pub struct AcceptedSession {
    pub session: Session,
    pub reliable: SessionReceiver,
    pub unreliable: SessionReceiver,
}

impl Session {
    /// Spawns the background driver for an already-negotiated-enough [`SansConnection`]
    /// (the initial offer/answer and, for trickle ICE, the first candidate should already
    /// be applied - see [`crate::transport::listener`]/[`crate::transport::stream`]), and
    /// returns the session handle, the receivers of its two data channels, and a receiver
    /// that resolves once both channels are open.
    pub(crate) fn spawn(
        socket: Arc<UdpSocket>,
        connection: SansConnection,
        local: Addr,
        remote: Addr,
    ) -> (
        Self,
        SessionReceiver,
        SessionReceiver,
        oneshot::Receiver<()>,
    ) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);
        let (unreliable_tx, unreliable_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();
        let close_token = CancellationToken::new();

        let task = Self::drive(
            socket,
            connection,
            command_rx,
            packet_tx,
            unreliable_tx,
            Some(ready_tx),
            close_token.clone(),
        );

        let guard = Arc::new(TaskGuard {
            close_token: close_token.clone(),
            task,
        });

        let session = Self {
            local_addr: local,
            remote_addr: remote,
            command_tx,
            close_token,
            _guard: guard.clone(),
        };

        (
            session,
            SessionReceiver {
                rx: packet_rx,
                _guard: guard.clone(),
            },
            SessionReceiver {
                rx: unreliable_rx,
                _guard: guard,
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
        close_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut wake = Instant::now() + MAX_IDLE;
            let mut remote_addr = None;
            let mut rtt = None;
            let mut player: Option<Arc<PlayerInfo>> = None;

            'drive: loop {
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
                        Some(Command::Send(channel, data, reply)) => {
                            let _ = reply.send(connection.send(channel, data).map_err(NethernetError::from));
                        }
                        Some(Command::Signal(signal)) => {
                            if let Err(e) = connection.handle_signal(&signal) {
                                tracing::debug!("signal handling error: {e}");
                            }
                        }
                        Some(Command::RemoteAddr(reply)) => {
                            let _ = reply.send(remote_addr);
                        }
                        Some(Command::Rtt(reply)) => {
                            let _ = reply.send(rtt);
                        }
                        Some(Command::SetPlayer(new_player)) => {
                            player = Some(new_player);
                        }
                        Some(Command::Player(reply)) => {
                            let _ = reply.send(player.clone());
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
                            remote_addr = connection.remote_addr();
                            if let Some(tx) = ready_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                        SessionOutput::Event(SessionEvent::Failed) => {
                            tracing::debug!("session transport failed, closing");
                            break 'drive;
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

                rtt = connection.rtt();

                let now = Instant::now();
                wake = connection.poll_timeout(now).unwrap_or(now + MAX_IDLE);
            }

            close_token.cancel();
        })
    }

    /// Sends data over the session using the reliable data channel, splitting the
    /// payload into protocol segments as needed.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Reliable, data).await
    }

    /// Sends data over the session using the unreliable data channel.
    ///
    /// Data sent over a channel that was opened out of band is dropped by remote
    /// connections that did not open the matching channel themselves.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Unreliable, data).await
    }

    async fn send_on(&self, channel: Channel, data: Bytes) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Send(channel, data, reply_tx))
            .map_err(|_| NethernetError::ConnectionClosed)?;
        reply_rx
            .await
            .map_err(|_| NethernetError::ConnectionClosed)?
    }

    /// Shuts down the session by stopping its background driver.
    ///
    /// After this call the session is considered closed; calling `close` again is a
    /// no-op.
    pub async fn close(&self) -> Result<()> {
        self.close_token.cancel();
        Ok(())
    }

    /// Returns the local address of the session.
    pub async fn local_addr(&self) -> Addr {
        self.local_addr.clone()
    }

    /// Returns the address of the remote connection, once known.
    pub async fn remote_addr(&self) -> Addr {
        let (reply_tx, reply_rx) = oneshot::channel();
        let socket_addr = match self.command_tx.send(Command::RemoteAddr(reply_tx)) {
            Ok(()) => reply_rx.await.ok().flatten(),
            Err(_) => None,
        };
        Addr {
            socket_addr,
            ..self.remote_addr.clone()
        }
    }

    /// The current round-trip-time estimate, once the data channels are open.
    pub async fn rtt(&self) -> Option<Duration> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.command_tx.send(Command::Rtt(reply_tx)).is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    /// Records the identity the connection was accepted with.
    pub async fn set_player(&self, player: Arc<PlayerInfo>) {
        let _ = self.command_tx.send(Command::SetPlayer(player));
    }

    /// The identity the connection was accepted with, or [`None`] when identities are not
    /// validated or the connection was dialed rather than accepted.
    ///
    /// Everything it claims is only as trustworthy as the policy the offer was validated
    /// with, and only its public key is bound to a key the peer had to hold.
    pub async fn player(&self) -> Option<Arc<PlayerInfo>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.command_tx.send(Command::Player(reply_tx)).is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    /// Resolves once the session has been closed.
    pub async fn closed(&self) {
        self.close_token.cancelled().await
    }

    /// Reports whether the session has been closed.
    pub async fn is_closed(&self) -> bool {
        self.close_token.is_cancelled()
    }
}

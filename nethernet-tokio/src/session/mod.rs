//! A connected session driven by one task, with reliable and unreliable channels and peer metadata.
pub(crate) mod command;

pub(crate) use command::Command;

use crate::addr::Addr;
use crate::error::{NetherError, Result};
use bytes::Bytes;
use nethernet::connection::{Connection as SansConnection, ConnectionInput};
use nethernet::identity::PlayerInfo;
use nethernet::sans::Sans;
pub use nethernet::session::Channel;
use nethernet::session::{SessionEvent, SessionOutput};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MAX_IDLE: Duration = Duration::from_secs(1);

const PACKET_CHANNEL_CAPACITY: usize = 1024;

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

/// Cloneable handle; the connection closes once every handle and receiver is dropped.
#[derive(Clone)]
pub struct Session {
    local_addr: Addr,
    remote_addr: Addr,
    command_tx: mpsc::UnboundedSender<Command>,
    close_token: CancellationToken,
    _guard: Arc<TaskGuard>,
}

/// Incoming messages of one channel; yields None once the connection closes.
pub struct SessionReceiver {
    rx: mpsc::Receiver<Bytes>,
    _guard: Arc<TaskGuard>,
}

impl SessionReceiver {
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        Ok(self.rx.recv().await)
    }

    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.rx.poll_recv(cx)
    }
}

/// A connected session with its reliable and unreliable receivers.
pub struct AcceptedSession {
    pub session: Session,
    pub reliable: SessionReceiver,
    pub unreliable: SessionReceiver,
}

impl Session {
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
            let mut host: Option<String> = None;

            'drive: loop {
                tokio::select! {
                    biased;

                    _ = close_token.cancelled() => break,
                    received = socket.recv_from(&mut buf) => match received {
                        Ok((n, from)) => {
                            let now = Instant::now();
                            let input = ConnectionInput::Packet(buf[..n].into(), from, now);
                            if let Err(e) = connection.handle(input) {
                                tracing::debug!("packet handling error: {e}");
                            }
                        }
                        Err(e) => tracing::debug!("recv error: {e}"),
                    },
                    command = commands.recv() => match command {
                        Some(Command::Send(channel, data, reply)) => {
                            let result = connection
                                .handle(ConnectionInput::Send(channel, data, Instant::now()))
                                .map_err(NetherError::from);
                            let _ = reply.send(result);
                        }
                        Some(Command::Signal(signal)) => {
                            if let Err(e) = connection.handle(ConnectionInput::Signal(signal, Instant::now())) {
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
                        Some(Command::SetHost(new_host)) => {
                            host = Some(new_host);
                        }
                        Some(Command::Host(reply)) => {
                            let _ = reply.send(host.clone());
                        }
                        None => break,
                    },
                    _ = tokio::time::sleep_until(wake.into()) => {
                        let now = Instant::now();
                        if let Err(e) = connection.handle(ConnectionInput::Timeout(now)) {
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
                        SessionOutput::Wait(wait) => {
                            wake = Instant::now() + wait.min(MAX_IDLE);
                        }
                    }
                }

                rtt = connection.rtt();
            }

            close_token.cancel();
        })
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Reliable, data).await
    }

    /// The message must fit one segment (guide section 6.1).
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.send_on(Channel::Unreliable, data).await
    }

    async fn send_on(&self, channel: Channel, data: Bytes) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Send(channel, data, reply_tx))
            .map_err(|_| NetherError::ConnectionClosed)?;
        reply_rx.await.map_err(|_| NetherError::ConnectionClosed)?
    }

    /// Starts closing and returns without waiting for teardown.
    pub async fn close(&self) -> Result<()> {
        self.close_token.cancel();
        Ok(())
    }

    pub async fn local_addr(&self) -> Addr {
        self.local_addr.clone()
    }

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

    /// None until a round trip time has been measured.
    pub async fn rtt(&self) -> Option<Duration> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.command_tx.send(Command::Rtt(reply_tx)).is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    /// Records the validated identity of the peer; the HTTP server sets it after admission.
    pub async fn set_player(&self, player: Arc<PlayerInfo>) {
        let _ = self.command_tx.send(Command::SetPlayer(player));
    }

    pub async fn player(&self) -> Option<Arc<PlayerInfo>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.command_tx.send(Command::Player(reply_tx)).is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    /// Records the Host header of the offer request, HTTP signaling only.
    pub async fn set_host(&self, host: String) {
        let _ = self.command_tx.send(Command::SetHost(host));
    }

    pub async fn host(&self) -> Option<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.command_tx.send(Command::Host(reply_tx)).is_err() {
            return None;
        }
        reply_rx.await.ok().flatten()
    }

    pub async fn closed(&self) {
        self.close_token.cancelled().await
    }

    pub async fn is_closed(&self) -> bool {
        self.close_token.is_cancelled()
    }
}

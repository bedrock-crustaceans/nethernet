use crate::addr::Addr;
use crate::error::{NetherError, Result, SignalErrorCode};
use crate::protocol::{Signal, SignalType};
use crate::session::{AcceptedSession, Command, Session};
use crate::signaling::ServerSignaling;
use crate::transport::{ConnectionConfig, local_bind_addr};
use futures::{Stream, StreamExt};
use nethernet::admission::OfferPolicy;
use nethernet::connection::IceMode;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Signals an error back to the remote connection referenced by the IDs.
async fn signal_error(
    signaling: &ServerSignaling,
    connection_id: u64,
    network_id: String,
    code: SignalErrorCode,
) {
    if let Err(e) = signaling
        .signal(Signal::error(connection_id, code, network_id))
        .await
    {
        tracing::debug!("Failed to signal error: {}", e);
    }
}

/// Connections are referenced by both the remote network ID and the connection ID, as
/// connection IDs are only unique within a single network.
type ConnectionKey = (String, u64);

/// Per-connection dispatch table, owned entirely by the signal handler task; dropping it
/// (when that task ends) drops every sender in it, which is what lets a forwarder task
/// waiting on the matching receiver see the channel close.
type SignalDispatchers = HashMap<ConnectionKey, mpsc::UnboundedSender<Signal>>;

/// NetherNet listener - accepts NetherNet connections
pub struct NetherServer {
    incoming: mpsc::UnboundedReceiver<AcceptedSession>,
    local_addr: Addr,
    cancel_token: CancellationToken,
    signal_handler_task: Option<JoinHandle<()>>,
}

impl NetherServer {
    /// Create a new [`NetherServer`] on the local network of the signaling implementation.
    ///
    /// The returned listener is ready to accept inbound sessions. It initializes internal
    /// queues and dispatch structures, and spawns a background task to process signaling
    /// events; dropping the listener cancels that task.
    pub async fn bind(signaling: impl Into<ServerSignaling>) -> Result<Self> {
        Self::bind_with(signaling, ConnectionConfig::default()).await
    }

    /// Creates a [`NetherServer`] using the timeouts of the given configuration.
    ///
    /// # Errors
    ///
    /// [`NetherError::IdentityRequired`] when the signaling is HTTP and the configuration
    /// has no identity, since a vanilla client refuses answers that carry none. Setting
    /// [`ConnectionConfig::allow_unsigned_answers`] opts out.
    pub async fn bind_with(
        signaling: impl Into<ServerSignaling>,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let signaling: ServerSignaling = signaling.into();
        if signaling.requires_identity()
            && config.identity.is_none()
            && !config.allow_unsigned_answers
        {
            return Err(NetherError::IdentityRequired);
        }
        let local_addr = Addr::network(signaling.network_id());
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();

        let signal_handler_task =
            Self::start_signal_handler(signaling, incoming_tx, cancel_token.clone(), config);

        let listener = Self {
            incoming: incoming_rx,
            local_addr,
            cancel_token,
            signal_handler_task: Some(signal_handler_task),
        };

        Ok(listener)
    }

    fn start_signal_handler(
        signaling: ServerSignaling,
        incoming_tx: mpsc::UnboundedSender<AcceptedSession>,
        cancel_token: CancellationToken,
        config: ConnectionConfig,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut dispatchers: SignalDispatchers = HashMap::new();
            let mut signals = signaling.signals();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    signal = signals.next() => {
                        match signal {
                            Some(signal) => {
                                match signal.signal_type {
                                    SignalType::Offer => {
                                        if let Err(e) = Self::handle_offer(
                                            signal,
                                            &signaling,
                                            &incoming_tx,
                                            &mut dispatchers,
                                            config.clone(),
                                        )
                                        .await
                                        {
                                            tracing::debug!("Failed to handle offer: {}", e);
                                        }
                                    }
                                    SignalType::Answer | SignalType::Candidate | SignalType::Error => {
                                        // Dispatch to per-connection channel
                                        let key = (signal.network_id.clone(), signal.connection_id);
                                        if let Some(tx) = dispatchers.get(&key) {
                                            let _ = tx.send(signal);
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        })
    }

    /// Answers an offer signaled by a remote connection and establishes the connection
    /// once it is ready.
    async fn handle_offer(
        signal: Signal,
        signaling: &ServerSignaling,
        incoming_tx: &mpsc::UnboundedSender<AcceptedSession>,
        dispatchers: &mut SignalDispatchers,
        config: ConnectionConfig,
    ) -> Result<()> {
        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();

        let cancel_token = config.cancel_token.clone();
        let result = tokio::select! {
            _ = cancel_token.cancelled() => Err((None, NetherError::ConnectionClosed)),
            result = Self::answer_offer(signal, signaling, incoming_tx, dispatchers, config.clone()) => result,
        };

        match result {
            Ok(()) => Ok(()),
            Err((code, e)) => {
                if let Some(code) = code {
                    signal_error(signaling, connection_id, network_id, code).await;
                }
                Err(e)
            }
        }
    }

    /// Answers the offer, reporting the error code to be signaled back to the remote
    /// connection when a step fails.
    async fn answer_offer(
        signal: Signal,
        signaling: &ServerSignaling,
        incoming_tx: &mpsc::UnboundedSender<AcceptedSession>,
        dispatchers: &mut SignalDispatchers,
        config: ConnectionConfig,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NetherError)> {
        let remote_address = signaling
            .remote_address(&Addr::new(signal.network_id.clone(), signal.connection_id))
            .await;

        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();
        let key = (network_id.clone(), connection_id);

        let signaled_player = signaling
            .player(&Addr::new(network_id.clone(), connection_id))
            .await;

        let signaled_host = signaling
            .host(&Addr::new(network_id.clone(), connection_id))
            .await;

        let ice_mode = if signaling.disable_trickle_ice() {
            IceMode::Full
        } else {
            IceMode::Trickle
        };
        let mut policy =
            OfferPolicy::new(ice_mode).with_inferred_peer_candidates(config.infer_peer_candidates);
        if let Some(identity) = &config.identity {
            policy = policy.with_identity(identity);
        }
        if !signaling.validates_offers()
            && let Some(trust) = &config.token_trust
        {
            policy = policy.with_token_trust(trust);
        }

        let admitted = policy
            .admit(&signal, remote_address, SystemTime::now())
            .map_err(|e| (Some(e.code()), NetherError::from(e)))?;

        let socket = Arc::new(UdpSocket::bind(local_bind_addr()).await.map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NetherError::from(e),
            )
        })?);
        let bound_addr = socket.local_addr().map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NetherError::from(e),
            )
        })?;

        let answered = admitted
            .answer(bound_addr, Instant::now())
            .map_err(|e| (Some(e.code()), NetherError::from(e)))?;
        let player = answered.player.map(Arc::new).or(signaled_player);
        let connection = answered.connection;

        for line in &answered.inferred {
            tracing::debug!("Inferred candidate for the peer: {}", line);
        }
        for outgoing in answered.signals {
            signaling.signal(outgoing).await.map_err(|e| (None, e))?;
        }

        let local = Addr::new(signaling.network_id(), connection_id);
        let remote = Addr::new(network_id.clone(), connection_id);

        let (session, reliable, unreliable, ready_rx) =
            Session::spawn(socket, connection, local, remote);

        if let Some(player) = player {
            session.set_player(player).await;
        }
        if let Some(host) = signaled_host {
            session.set_host(host).await;
        }

        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        dispatchers.insert(key, signal_tx);
        spawn_late_signal_forwarder(signal_rx, session.signal_sender());

        let incoming_tx = incoming_tx.clone();
        let signaling = signaling.clone();
        tokio::spawn(async move {
            let cancel_token = config.cancel_token.clone();
            let result = tokio::select! {
                _ = cancel_token.cancelled() => Err((None, NetherError::ConnectionClosed)),
                result = wait_ready(ready_rx, config.timeouts.establish()) => result,
            };

            match result {
                Ok(()) => {
                    let _ = incoming_tx.send(AcceptedSession {
                        session,
                        reliable,
                        unreliable,
                    });
                }
                Err((code, e)) => {
                    tracing::debug!("Failed to establish incoming connection: {}", e);
                    if let Some(code) = code {
                        signal_error(&signaling, connection_id, network_id, code).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Waits for and returns the next inbound session.
    pub async fn accept(&mut self) -> Result<AcceptedSession> {
        self.incoming
            .recv()
            .await
            .ok_or(NetherError::ConnectionClosed)
    }

    /// Closes the listener and every session that has not been accepted yet.
    ///
    /// Blocked calls to [`NetherServer::accept`] return
    /// [`NetherError::ConnectionClosed`] once the listener is closed.
    pub async fn close(&mut self) -> Result<()> {
        self.cancel_token.cancel();
        self.incoming.close();

        while let Ok(accepted) = self.incoming.try_recv() {
            if let Err(e) = accepted.session.close().await {
                tracing::debug!("Failed to close pending session: {}", e);
            }
        }

        // Waiting for the task to actually finish, rather than just cancelling it, is
        // what guarantees its dispatch table (and every sender in it) is dropped before
        // this returns.
        if let Some(task) = self.signal_handler_task.take() {
            let _ = task.await;
        }

        Ok(())
    }

    /// Address of the local network this listener accepts connections on.
    pub fn local_addr(&self) -> &Addr {
        &self.local_addr
    }
}

/// Keeps forwarding further signals (e.g. a late-trickled or redundant candidate, or a
/// remote error) into the now-running connection, until either the dispatcher's route is
/// exhausted or the connection stops (which drops the driver's command receiver, so
/// `command_tx.send` starts failing).
fn spawn_late_signal_forwarder(
    mut signals: mpsc::UnboundedReceiver<Signal>,
    command_tx: mpsc::UnboundedSender<Command>,
) {
    tokio::spawn(async move {
        while let Some(signal) = signals.recv().await {
            if signal.signal_type != SignalType::Candidate {
                continue;
            }
            if command_tx.send(Command::Signal(signal)).is_err() {
                break;
            }
        }
    });
}

/// Waits for the session to signal readiness (both data channels open), or times out.
async fn wait_ready(
    ready_rx: tokio::sync::oneshot::Receiver<()>,
    timeout: std::time::Duration,
) -> std::result::Result<(), (Option<SignalErrorCode>, NetherError)> {
    tokio::time::timeout(timeout, ready_rx)
        .await
        .map_err(|_| {
            (
                Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                NetherError::Timeout,
            )
        })?
        .map_err(|_| (None, NetherError::ConnectionClosed))
}

impl Drop for NetherServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl Stream for NetherServer {
    type Item = AcceptedSession;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().incoming.poll_recv(cx)
    }
}

use crate::addr::Addr;
use crate::error::{NethernetError, Result, SignalErrorCode};
use crate::protocol::{Signal, SignalType};
use crate::session::{AcceptedSession, Command, Session};
use crate::signaling::Signaling;
use crate::transport::{ConnectionConfig, local_bind_addr};
use futures::{Stream, StreamExt};
use nethernet::connection::{Connection as SansConnection, IceMode};
use nethernet::identity::{PlayerInfo, validate_sdp};
use nethernet::session::Session as SansSession;
use nethernet::util::candidate;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Signals an error back to the remote connection referenced by the IDs.
async fn signal_error<S: Signaling>(
    signaling: &Arc<S>,
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
pub struct NethernetListener<S: Signaling> {
    incoming: mpsc::UnboundedReceiver<AcceptedSession>,
    local_addr: Addr,
    cancel_token: CancellationToken,
    signal_handler_task: Option<JoinHandle<()>>,
    _phantom: PhantomData<S>,
}

impl<S: Signaling + 'static> NethernetListener<S> {
    /// Create a new [`NethernetListener`] on the local network of the signaling implementation.
    ///
    /// The returned listener is ready to accept inbound sessions. It initializes internal
    /// queues and dispatch structures, and spawns a background task to process signaling
    /// events; dropping the listener cancels that task.
    pub async fn bind(signaling: S) -> Result<Self> {
        Self::bind_with(signaling, ConnectionConfig::default()).await
    }

    /// Creates a [`NethernetListener`] using the timeouts of the given configuration.
    pub async fn bind_with(signaling: S, config: ConnectionConfig) -> Result<Self> {
        let signaling = Arc::new(signaling);
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
            _phantom: PhantomData,
        };

        Ok(listener)
    }

    fn start_signal_handler(
        signaling: Arc<S>,
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
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<AcceptedSession>,
        dispatchers: &mut SignalDispatchers,
        config: ConnectionConfig,
    ) -> Result<()> {
        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();

        let cancel_token = config.cancel_token.clone();
        let result = tokio::select! {
            _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
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
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<AcceptedSession>,
        dispatchers: &mut SignalDispatchers,
        config: ConnectionConfig,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
        let (remote_description, remote_candidates) = SansConnection::parse_offer(&signal)
            .map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToSetRemoteDescription),
                    e.into(),
                )
            })?;

        let remote_address = signaling
            .remote_address(&Addr::new(signal.network_id.clone(), signal.connection_id))
            .await;

        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();
        let key = (network_id.clone(), connection_id);

        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        dispatchers.insert(key.clone(), signal_tx);
        // A peer that cannot prove who it is has an offer anyone could have replayed
        let signaled_player = signaling
            .player(&Addr::new(network_id.clone(), connection_id))
            .await;
        let player = match &config.token_trust {
            Some(trust) => match validate_sdp(&signal.data, trust, SystemTime::now()) {
                Ok(claims) => Some(Arc::new(PlayerInfo::new(
                    claims,
                    network_id.clone(),
                    remote_address,
                ))),
                Err(e) => {
                    return Err((
                        Some(SignalErrorCode::NotLoggedIn),
                        NethernetError::Identity(e),
                    ));
                }
            },
            None => signaled_player,
        };

        let socket = Arc::new(UdpSocket::bind(local_bind_addr()).await.map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NethernetError::from(e),
            )
        })?);
        let bound_addr = socket.local_addr().map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NethernetError::from(e),
            )
        })?;

        let (session, description) = SansSession::new(bound_addr, false).map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NethernetError::from(e),
            )
        })?;

        // Non-trickle connections carry every local candidate in the answer itself
        let ice_mode = if signaling.disable_trickle_ice() {
            IceMode::Full
        } else {
            IceMode::Trickle
        };

        let (mut connection, signals) = SansConnection::accept(
            session,
            description,
            &signal,
            remote_description,
            remote_candidates,
            ice_mode,
        )
        .map_err(|e| (Some(SignalErrorCode::FailedToCreateAnswer), e.into()))?;

        let mut signals_out = signals.into_iter();
        let answer = signals_out
            .next()
            .expect("Connection::accept always returns an answer signal first");

        // Clients pin the key an answer is signed with, so one that is not signed prompts
        // the player on every join
        let answer_data = match &config.identity {
            Some(identity) => identity.augment(&answer.data).map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToCreateAnswer),
                    NethernetError::Identity(e),
                )
            })?,
            None => answer.data,
        };

        signaling
            .signal(Signal::answer(
                connection_id,
                answer_data,
                network_id.clone(),
            ))
            .await
            .map_err(|e| (None, e))?;
        for trickled in signals_out {
            signaling.signal(trickled).await.map_err(|e| (None, e))?;
        }

        if config.infer_peer_candidates && !candidate::has_routable_host_candidate(&signal.data) {
            for line in candidate::inferred_peer_candidates(&signal.data, remote_address) {
                tracing::debug!("Inferred candidate for the peer: {}", line);
                if let Err(e) = connection.handle_signal(&Signal::candidate(
                    connection_id,
                    line,
                    network_id.clone(),
                )) {
                    tracing::warn!("Failed to add inferred candidate: {}", e);
                }
            }
        }

        let local = Addr::new(signaling.network_id(), connection_id);
        let remote = Addr::new(network_id.clone(), connection_id);

        let (session, reliable, unreliable, ready_rx) =
            Session::spawn(socket, connection, local, remote);

        if let Some(player) = player {
            session.set_player(player).await;
        }

        spawn_late_signal_forwarder(signal_rx, session.signal_sender());

        let incoming_tx = incoming_tx.clone();
        let signaling = signaling.clone();
        tokio::spawn(async move {
            let cancel_token = config.cancel_token.clone();
            let result = tokio::select! {
                _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
                result = wait_ready(ready_rx, config.timeouts.start + config.timeouts.channel) => result,
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
            .ok_or(NethernetError::ConnectionClosed)
    }

    /// Closes the listener and every session that has not been accepted yet.
    ///
    /// Blocked calls to [`NethernetListener::accept`] return
    /// [`NethernetError::ConnectionClosed`] once the listener is closed.
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
) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
    tokio::time::timeout(timeout, ready_rx)
        .await
        .map_err(|_| {
            (
                Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                NethernetError::Timeout,
            )
        })?
        .map_err(|_| (None, NethernetError::ConnectionClosed))
}

impl<S: Signaling> Drop for NethernetListener<S> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<S: Signaling + 'static + Unpin> Stream for NethernetListener<S> {
    type Item = AcceptedSession;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().incoming.poll_recv(cx)
    }
}

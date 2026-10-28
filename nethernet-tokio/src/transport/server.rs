use crate::addr::Addr;
use crate::error::{NetherError, Result, SignalErrorCode};
use crate::protocol::{Signal, SignalType};
use crate::session::{AcceptedSession, Command, Session, SessionSocket};
use crate::signaling::ServerSignaling;
use crate::transport::pending::PendingOffers;
use crate::transport::shared::SharedSocket;
use crate::transport::{ConnectionConfig, local_bind_addr};
use futures::{Stream, StreamExt};
use nethernet::admission::OfferPolicy;
use nethernet::connection::IceMode;
use nethernet::identity::TokenTrust;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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

type ConnectionKey = (String, u64);

type SignalDispatchers = HashMap<ConnectionKey, mpsc::UnboundedSender<Signal>>;

type SharedTrust = Arc<RwLock<Option<TokenTrust>>>;

/// Answers offers arriving on its signaling and yields the connected sessions.
pub struct NetherServer {
    incoming: mpsc::UnboundedReceiver<AcceptedSession>,
    local_addr: Addr,
    signaling: ServerSignaling,
    token_trust: SharedTrust,
    cancel_token: CancellationToken,
    signal_handler_task: Option<JoinHandle<()>>,
}

impl NetherServer {
    pub async fn bind(signaling: impl Into<ServerSignaling>) -> Result<Self> {
        Self::bind_with(signaling, ConnectionConfig::default()).await
    }

    /// Fails with IdentityRequired when the signaling needs signed answers and the config has no identity.
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
        let shared = match config.media_addr {
            Some(addr) => Some(Arc::new(
                SharedSocket::bind(addr, local_bind_addr().ip()).await?,
            )),
            None => None,
        };
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let token_trust = Arc::new(RwLock::new(config.token_trust.clone()));

        let signal_handler_task = Self::start_signal_handler(
            signaling.clone(),
            incoming_tx,
            cancel_token.clone(),
            config,
            token_trust.clone(),
            shared,
        );

        let listener = Self {
            incoming: incoming_rx,
            local_addr,
            signaling,
            token_trust,
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
        token_trust: SharedTrust,
        shared: Option<Arc<SharedSocket>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut dispatchers: SignalDispatchers = HashMap::new();
            let pending = PendingOffers::default();
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
                                        dispatchers.retain(|_, tx| !tx.is_closed());
                                        let mut config = config.clone();
                                        config.token_trust = token_trust
                                            .read()
                                            .unwrap_or_else(PoisonError::into_inner)
                                            .clone();
                                        if let Err(e) = Self::handle_offer(
                                            signal,
                                            &signaling,
                                            &incoming_tx,
                                            &mut dispatchers,
                                            &pending,
                                            config,
                                            shared.clone(),
                                        )
                                        .await
                                        {
                                            tracing::debug!("Failed to handle offer: {}", e);
                                        }
                                    }
                                    SignalType::Answer | SignalType::Candidate | SignalType::Error => {
                                        let key = (signal.network_id.clone(), signal.connection_id);
                                        if let Some(tx) = dispatchers.get(&key)
                                            && tx.send(signal).is_err()
                                        {
                                            dispatchers.remove(&key);
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

    async fn handle_offer(
        signal: Signal,
        signaling: &ServerSignaling,
        incoming_tx: &mpsc::UnboundedSender<AcceptedSession>,
        dispatchers: &mut SignalDispatchers,
        pending: &PendingOffers,
        config: ConnectionConfig,
        shared: Option<Arc<SharedSocket>>,
    ) -> Result<()> {
        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();

        let cancel_token = config.cancel_token.clone();
        let result = tokio::select! {
            _ = cancel_token.cancelled() => Err((None, NetherError::ConnectionClosed)),
            result = Self::answer_offer(signal, signaling, incoming_tx, dispatchers, pending, config.clone(), shared) => result,
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

    async fn answer_offer(
        signal: Signal,
        signaling: &ServerSignaling,
        incoming_tx: &mpsc::UnboundedSender<AcceptedSession>,
        dispatchers: &mut SignalDispatchers,
        pending: &PendingOffers,
        config: ConnectionConfig,
        shared: Option<Arc<SharedSocket>>,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NetherError)> {
        let slot = pending
            .try_admit(
                &signal.network_id,
                config.max_pending,
                config.max_pending_per_network_id,
            )
            .ok_or_else(|| {
                (
                    Some(SignalErrorCode::IncomingConnectionIgnored),
                    NetherError::PendingCountExceeded(signal.network_id.clone()),
                )
            })?;

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
        policy = policy.with_establish_deadline(config.timeouts.establish());
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

        let (bound_addr, owned) = match &shared {
            Some(shared) => (shared.advertised_addr(), None),
            None => {
                let socket = UdpSocket::bind(local_bind_addr())
                    .await
                    .map_err(peer_connection_failed)?;
                let bound_addr = socket.local_addr().map_err(peer_connection_failed)?;
                (bound_addr, Some(Arc::new(socket)))
            }
        };

        let answered = admitted
            .answer(bound_addr, Instant::now())
            .map_err(|e| (Some(e.code()), NetherError::from(e)))?;
        let socket = match (owned, &shared) {
            (Some(socket), _) => SessionSocket::Owned(socket),
            (None, Some(shared)) => {
                SessionSocket::Shared(shared.route(answered.local_ufrag.clone()))
            }
            (None, None) => unreachable!("a socket is bound whenever none is shared"),
        };
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
        let closed = session.clone();
        spawn_late_signal_forwarder(signal_rx, session.signal_sender(), async move {
            closed.closed().await
        });

        let incoming_tx = incoming_tx.clone();
        let signaling = signaling.clone();
        tokio::spawn(async move {
            let cancel_token = config.cancel_token.clone();
            let result = tokio::select! {
                _ = cancel_token.cancelled() => Err((None, NetherError::ConnectionClosed)),
                result = wait_ready(ready_rx, config.timeouts.establish()) => result,
            };
            drop(slot);

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
                    if let Err(e) = session.close().await {
                        tracing::debug!("Failed to close the unestablished session: {}", e);
                    }
                    if let Some(code) = code {
                        signal_error(&signaling, connection_id, network_id, code).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Next connected session; fails with ConnectionClosed once the server is closed.
    pub async fn accept(&mut self) -> Result<AcceptedSession> {
        self.incoming
            .recv()
            .await
            .ok_or(NetherError::ConnectionClosed)
    }

    /// Stops signaling and closes sessions that were not yet accepted.
    pub async fn close(&mut self) -> Result<()> {
        self.cancel_token.cancel();
        self.incoming.close();

        while let Ok(accepted) = self.incoming.try_recv() {
            if let Err(e) = accepted.session.close().await {
                tracing::debug!("Failed to close pending session: {}", e);
            }
        }

        if let Some(task) = self.signal_handler_task.take() {
            let _ = task.await;
        }

        Ok(())
    }

    pub fn local_addr(&self) -> &Addr {
        &self.local_addr
    }

    /// Replaces how later offers are authenticated; `None` skips validation.
    ///
    /// Over HTTP signaling the signaler authenticates offers, so its trust is replaced instead.
    pub fn set_token_trust(&self, trust: Option<TokenTrust>) {
        match &self.signaling {
            ServerSignaling::Http(signaling) => signaling.set_token_trust(trust),
            ServerSignaling::Lan(_) => {
                *self
                    .token_trust
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = trust;
            }
        }
    }
}

fn spawn_late_signal_forwarder(
    mut signals: mpsc::UnboundedReceiver<Signal>,
    command_tx: mpsc::UnboundedSender<Command>,
    closed: impl Future<Output = ()> + Send + 'static,
) {
    tokio::spawn(async move {
        tokio::pin!(closed);
        loop {
            let signal = tokio::select! {
                _ = &mut closed => break,
                signal = signals.recv() => match signal {
                    Some(signal) => signal,
                    None => break,
                },
            };
            if signal.signal_type != SignalType::Candidate {
                continue;
            }
            if command_tx.send(Command::Signal(signal)).is_err() {
                break;
            }
        }
    });
}

fn peer_connection_failed(e: std::io::Error) -> (Option<SignalErrorCode>, NetherError) {
    (
        Some(SignalErrorCode::FailedToCreatePeerConnection),
        NetherError::from(e),
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn forwarder_stops_when_its_session_closes() {
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let session_closed = CancellationToken::new();
        spawn_late_signal_forwarder(
            signal_rx,
            command_tx,
            session_closed.clone().cancelled_owned(),
        );

        session_closed.cancel();

        tokio::time::timeout(Duration::from_secs(1), signal_tx.closed())
            .await
            .expect("the forwarder should drop its receiver once the session closes");
    }

    #[tokio::test]
    async fn a_trust_set_on_a_server_over_http_reaches_the_signaler() {
        use crate::signaling::http::server::tests::{post_offer, signed_offer};
        use crate::signaling::http::{HttpServerConfig, HttpSignalingServer};

        let signaling = Arc::new(
            HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), HttpServerConfig::default())
                .await
                .unwrap(),
        );
        let server = NetherServer::bind_with(
            signaling.clone(),
            ConnectionConfig {
                allow_unsigned_answers: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        server.set_token_trust(Some(TokenTrust::Minecraft(Default::default())));

        assert_eq!(
            post_offer(signaling.local_addr(), &signed_offer()).await,
            "HTTP/1.1 401 Unauthorized"
        );
    }
}

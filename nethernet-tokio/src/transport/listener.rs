use crate::addr::Addr;
use crate::error::{NethernetError, Result, SignalErrorCode};
use crate::protocol::constants::{RELIABLE_CHANNEL, UNRELIABLE_CHANNEL};
use crate::protocol::webrtc::{format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::session::Session;
use crate::signaling::Signaling;
use crate::transport::{ConnectionConfig, build_peer_connection};
use futures::{Stream, StreamExt};
use nethernet::identity::{PlayerInfo, validate_sdp};
use nethernet::util::candidate;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    RTCIceCandidate, RTCIceGatheringState, RTCPeerConnectionIceEvent, RTCSessionDescription,
};

/// Connections are referenced by both the remote network ID and the connection ID, as
/// connection IDs are only unique within a single network.
type ConnectionKey = (String, u64);

type SignalDispatchers = Arc<Mutex<HashMap<ConnectionKey, mpsc::UnboundedSender<Signal>>>>;

/// Forwards the events of a peer connection answering an offer.
struct AnswerHandler {
    candidate_tx: mpsc::UnboundedSender<RTCIceCandidate>,
    gathering_tx: mpsc::UnboundedSender<RTCIceGatheringState>,
    data_channel_tx: mpsc::UnboundedSender<Arc<dyn DataChannel>>,
}

#[async_trait::async_trait]
impl webrtc::peer_connection::PeerConnectionEventHandler for AnswerHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let _ = self.candidate_tx.send(event.candidate);
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        let _ = self.gathering_tx.send(state);
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let _ = self.data_channel_tx.send(channel);
    }
}

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

/// NetherNet listener - accepts WebRTC connections
pub struct NethernetListener<S: Signaling> {
    incoming: mpsc::UnboundedReceiver<Arc<Session>>,
    local_addr: Addr,
    signal_dispatchers: SignalDispatchers,
    cancel_token: CancellationToken,
    _signal_handler_task: JoinHandle<()>,
    _phantom: PhantomData<S>,
}

impl<S: Signaling + 'static> NethernetListener<S> {
    /// Create a new [`NethernetListener`] on the local network of the signaling implementation.
    ///
    /// The returned listener is ready to accept inbound WebRTC sessions. It initializes internal queues and dispatch
    /// structures, and spawns a background task to process signaling events; dropping the listener cancels that task.
    pub async fn bind(signaling: S) -> Result<Self> {
        Self::bind_with(signaling, ConnectionConfig::default()).await
    }

    /// Creates a [`NethernetListener`] using the timeouts of the given configuration.
    pub async fn bind_with(signaling: S, config: ConnectionConfig) -> Result<Self> {
        let signaling = Arc::new(signaling);
        let local_addr = Addr::network(signaling.network_id());
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let signal_dispatchers = Arc::new(Mutex::new(HashMap::new()));
        let cancel_token = CancellationToken::new();

        // Start signal handler task
        let signal_handler_task = Self::start_signal_handler(
            signaling,
            incoming_tx,
            signal_dispatchers.clone(),
            cancel_token.clone(),
            config,
        );

        let listener = Self {
            incoming: incoming_rx,
            local_addr,
            signal_dispatchers,
            cancel_token,
            _signal_handler_task: signal_handler_task,
            _phantom: PhantomData,
        };

        Ok(listener)
    }

    fn start_signal_handler(
        signaling: Arc<S>,
        incoming_tx: mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: SignalDispatchers,
        cancel_token: CancellationToken,
        config: ConnectionConfig,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut signals = signaling.signals();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    signal = signals.next() => {
                        let Some(signal) = signal else { break };
                        match signal.signal_type {
                            SignalType::Offer => {
                                // Register the dispatcher before any answer can arrive,
                                // so no signal of this connection is missed
                                let key = (signal.network_id.clone(), signal.connection_id);
                                let (signal_tx, signal_rx) = mpsc::unbounded_channel();
                                signal_dispatchers.lock().await.insert(key, signal_tx);

                                let signaling = signaling.clone();
                                let incoming_tx = incoming_tx.clone();
                                let dispatchers = signal_dispatchers.clone();
                                let config = config.clone();
                                let connection_id = signal.connection_id;
                                let network_id = signal.network_id.clone();
                                tokio::spawn(async move {
                                    let result = Self::answer_offer(
                                        signal,
                                        &signaling,
                                        &incoming_tx,
                                        &dispatchers,
                                        config,
                                        signal_rx,
                                    )
                                    .await;
                                    if let Err((code, e)) = result {
                                        tracing::debug!("Failed to handle offer: {}", e);
                                        if let Some(code) = code {
                                            signal_error(
                                                &signaling,
                                                connection_id,
                                                network_id,
                                                code,
                                            )
                                            .await;
                                        }
                                    }
                                });
                            }
                            SignalType::Answer | SignalType::Candidate | SignalType::Error => {
                                // Dispatch to per-connection channel
                                let dispatchers = signal_dispatchers.lock().await;
                                let key = (signal.network_id.clone(), signal.connection_id);
                                if let Some(tx) = dispatchers.get(&key) {
                                    let _ = tx.send(signal);
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Answers the offer, reporting the error code to be signaled back to the remote
    /// connection when a step fails.
    async fn answer_offer(
        signal: Signal,
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: &SignalDispatchers,
        config: ConnectionConfig,
        signal_rx: mpsc::UnboundedReceiver<Signal>,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
        let cancel_token = config.cancel_token.clone();
        tokio::select! {
            _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
            result = Self::answer_offer_inner(
                signal,
                signaling,
                incoming_tx,
                signal_dispatchers,
                config,
                signal_rx,
            ) => result,
        }
    }

    async fn answer_offer_inner(
        signal: Signal,
        signaling: &Arc<S>,
        incoming_tx: &mpsc::UnboundedSender<Arc<Session>>,
        signal_dispatchers: &SignalDispatchers,
        config: ConnectionConfig,
        mut signal_rx: mpsc::UnboundedReceiver<Signal>,
    ) -> std::result::Result<(), (Option<SignalErrorCode>, NethernetError)> {
        let connection_id = signal.connection_id;
        let network_id = signal.network_id.clone();
        let key = (network_id.clone(), connection_id);

        let remote_offer = RTCSessionDescription::offer(signal.data.clone()).map_err(|e| {
            (
                Some(SignalErrorCode::FailedToSetRemoteDescription),
                NethernetError::WebRtc(e),
            )
        })?;

        let remote_address =
            signaling.remote_address(&Addr::new(network_id.clone(), connection_id));

        // A peer that cannot prove who it is has an offer anyone could have replayed
        let signaled_player = signaling.player(&Addr::new(network_id.clone(), connection_id));
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

        let (candidate_tx, candidate_rx) = mpsc::unbounded_channel();
        let (gathering_tx, gathering_rx) = mpsc::unbounded_channel();
        let (data_channel_tx, mut data_channel_rx) = mpsc::unbounded_channel();
        let handler = Arc::new(AnswerHandler {
            candidate_tx,
            gathering_tx,
            data_channel_tx,
        });

        let credentials = signaling
            .credentials()
            .await
            .map_err(|e| (Some(SignalErrorCode::SignalingTurnAuthFailed), e))?;
        let peer_connection = build_peer_connection(credentials.as_ref(), handler)
            .await
            .map_err(|e| (Some(SignalErrorCode::FailedToCreatePeerConnection), e))?;

        peer_connection
            .set_remote_description(remote_offer)
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToSetRemoteDescription),
                    NethernetError::WebRtc(e),
                )
            })?;

        if config.infer_peer_candidates && !candidate::has_routable_host_candidate(&signal.data) {
            for line in candidate::inferred_peer_candidates(&signal.data, remote_address) {
                let candidate = match parse_ice_candidate(&line) {
                    Ok(candidate) => candidate,
                    Err(e) => {
                        tracing::debug!("Failed to parse inferred candidate: {}", e);
                        continue;
                    }
                };

                tracing::debug!("Inferred candidate for the peer: {}", line);
                if let Err(e) = peer_connection.add_ice_candidate(candidate).await {
                    tracing::warn!("Failed to add inferred candidate: {}", e);
                }
            }
        }

        let answer = peer_connection.create_answer(None).await.map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreateAnswer),
                NethernetError::WebRtc(e),
            )
        })?;
        peer_connection
            .set_local_description(answer.clone())
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToSetLocalDescription),
                    NethernetError::WebRtc(e),
                )
            })?;

        // Trickle connections signal every gathered candidate of their own
        let disable_trickle_ice = signaling.disable_trickle_ice();
        if !disable_trickle_ice {
            let signaling = signaling.clone();
            let network_id = network_id.clone();
            tokio::spawn(async move {
                let mut index = 0usize;
                let mut candidate_rx = candidate_rx;
                while let Some(candidate) = candidate_rx.recv().await {
                    let result = signaling
                        .signal(Signal::candidate(
                            connection_id,
                            format_ice_candidate(index, &candidate, ""),
                            network_id.clone(),
                        ))
                        .await;
                    index += 1;
                    if result.is_err() {
                        break;
                    }
                }
            });
        }

        // Non-trickle connections carry every local candidate in the answer itself
        let answer_sdp = if disable_trickle_ice {
            wait_for_gathering_complete(gathering_rx, config.timeouts.start)
                .await
                .map_err(|e| (Some(SignalErrorCode::FailedToCreateAnswer), e))?;
            peer_connection
                .local_description()
                .await
                .ok_or((
                    Some(SignalErrorCode::FailedToCreateAnswer),
                    NethernetError::InvalidState("missing local description".to_string()),
                ))?
                .sdp
        } else {
            answer.sdp
        };

        // Clients pin the key an answer is signed with, so one that is not signed prompts
        // the player on every join
        let answer_sdp = match &config.identity {
            Some(identity) => identity.augment(&answer_sdp).map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToCreateAnswer),
                    NethernetError::Identity(e),
                )
            })?,
            None => answer_sdp,
        };

        let pc_for_candidates = peer_connection.clone();
        let candidate_cancel = CancellationToken::new();
        let candidate_cancel_for_task = candidate_cancel.clone();
        let dispatchers = signal_dispatchers.clone();
        let key_for_task = key.clone();
        tokio::spawn(async move {
            loop {
                let signal = tokio::select! {
                    _ = candidate_cancel_for_task.cancelled() => break,
                    signal = signal_rx.recv() => match signal {
                        Some(signal) => signal,
                        None => break,
                    },
                };
                match signal.signal_type {
                    SignalType::Candidate => match parse_ice_candidate(&signal.data) {
                        Ok(candidate) => {
                            if let Err(e) = pc_for_candidates.add_ice_candidate(candidate).await {
                                tracing::warn!("Failed to add remote candidate: {}", e);
                            }
                        }
                        Err(e) => tracing::warn!("Failed to parse remote candidate: {}", e),
                    },
                    SignalType::Error => {
                        let code = crate::transport::stream::parse_error_code(&signal.data);
                        tracing::debug!("Remote connection signaled an error: {:?}", code);
                        break;
                    }
                    _ => {}
                }
            }
            dispatchers.lock().await.remove(&key_for_task);
        });

        signaling
            .signal(Signal::answer(
                connection_id,
                answer_sdp,
                network_id.clone(),
            ))
            .await
            .map_err(|e| (None, e))?;

        let (reliable, unreliable) =
            wait_for_channels(&mut data_channel_rx, config.timeouts.channel)
                .await
                .map_err(|e| {
                    (
                        Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                        e,
                    )
                })?;
        wait_for_channel_open(reliable.clone(), config.timeouts.channel)
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                    e,
                )
            })?;
        wait_for_channel_open(unreliable.clone(), config.timeouts.channel)
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                    e,
                )
            })?;

        let session = Arc::new(Session::new(
            peer_connection,
            Addr::new(signaling.network_id(), connection_id),
            Addr::new(network_id, connection_id),
        ));
        if let Some(player) = player {
            session.set_player(player).await;
        }
        session
            .set_reliable_channel(reliable)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;
        session
            .set_unreliable_channel(unreliable)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;

        incoming_tx
            .send(session.clone())
            .map_err(|_| (None, NethernetError::ConnectionClosed))?;

        tokio::spawn(async move {
            session.closed().await;
            candidate_cancel.cancel();
        });

        Ok(())
    }

    /// Waits for and returns the next inbound session.
    pub async fn accept(&mut self) -> Result<Arc<Session>> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| NethernetError::ConnectionClosed)
    }

    /// Closes the listener and every session that has not been accepted yet.
    ///
    /// Blocked calls to [`NethernetListener::accept`] return
    /// [`NethernetError::ConnectionClosed`] once the listener is closed.
    pub async fn close(&mut self) -> Result<()> {
        self.cancel_token.cancel();
        self.incoming.close();

        while let Ok(session) = self.incoming.try_recv() {
            if let Err(e) = session.close().await {
                tracing::debug!("Failed to close pending session: {}", e);
            }
        }
        self.signal_dispatchers.lock().await.clear();

        Ok(())
    }

    /// Address of the local network this listener accepts connections on.
    pub fn local_addr(&self) -> &Addr {
        &self.local_addr
    }
}

/// Resolves once the gathering of local candidates has completed.
async fn wait_for_gathering_complete(
    mut gathering_rx: mpsc::UnboundedReceiver<RTCIceGatheringState>,
    timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(timeout, async move {
        while let Some(state) = gathering_rx.recv().await {
            if state == RTCIceGatheringState::Complete {
                return Ok(());
            }
        }
        Err(NethernetError::ConnectionClosed)
    })
    .await
    .map_err(|_| NethernetError::Timeout)??;
    Ok(())
}

/// Waits until the remote connection has created both data channels.
async fn wait_for_channels(
    data_channel_rx: &mut mpsc::UnboundedReceiver<Arc<dyn DataChannel>>,
    timeout: Duration,
) -> Result<(Arc<dyn DataChannel>, Arc<dyn DataChannel>)> {
    tokio::time::timeout(timeout, async {
        let mut reliable = None;
        let mut unreliable = None;
        while reliable.is_none() || unreliable.is_none() {
            let channel = data_channel_rx
                .recv()
                .await
                .ok_or(NethernetError::ConnectionClosed)?;
            let label = channel
                .label()
                .await
                .map_err(|e| NethernetError::DataChannel(e.to_string()))?;
            if label == RELIABLE_CHANNEL {
                reliable = Some(channel);
            } else if label == UNRELIABLE_CHANNEL {
                unreliable = Some(channel);
            }
        }
        Ok((
            reliable.expect("reliable channel set"),
            unreliable.expect("unreliable channel set"),
        ))
    })
    .await
    .map_err(|_| NethernetError::Timeout)?
}

/// Waits until the channel is open.
async fn wait_for_channel_open(channel: Arc<dyn DataChannel>, timeout: Duration) -> Result<()> {
    tokio::time::timeout(timeout, async move {
        while let Some(event) = channel.poll().await {
            if matches!(event, DataChannelEvent::OnOpen) {
                return Ok(());
            }
        }
        Err(NethernetError::ConnectionClosed)
    })
    .await
    .map_err(|_| NethernetError::Timeout)??;
    Ok(())
}

impl<S: Signaling> Drop for NethernetListener<S> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl<S: Signaling + 'static + Unpin> Stream for NethernetListener<S> {
    type Item = Arc<Session>;

    /// Polls the listener for the next inbound session, returning Pending if the internal queue is empty.
    ///
    /// This method delegates to the inner receiver's poll to produce the next [`Arc<Session>`].
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().incoming.poll_recv(cx)
    }
}

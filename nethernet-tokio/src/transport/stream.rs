use crate::addr::Addr;
use crate::error::{NethernetError, Result, SignalErrorCode};
use crate::protocol::constants::{RELIABLE_CHANNEL, UNRELIABLE_CHANNEL};
use crate::protocol::webrtc::{format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::session::Session;
use crate::signaling::Signaling;
use crate::transport::{ConnectionConfig, build_peer_connection};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::io::StreamReader;
use tokio_util::sync::ReusableBoxFuture;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    RTCIceCandidate, RTCIceGatheringState, RTCPeerConnectionIceEvent, RTCSessionDescription,
};

/// Parses the error code of a `CONNECTERROR` signal.
pub(crate) fn parse_error_code(data: &str) -> SignalErrorCode {
    data.trim().parse::<u32>().map_or(
        SignalErrorCode::SignalingUnknownError,
        SignalErrorCode::from,
    )
}

/// Forwards the events of a peer connection dialing a remote connection.
struct CandidateHandler {
    candidate_tx: mpsc::UnboundedSender<RTCIceCandidate>,
    gathering_tx: mpsc::UnboundedSender<RTCIceGatheringState>,
}

#[async_trait::async_trait]
impl webrtc::peer_connection::PeerConnectionEventHandler for CandidateHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let _ = self.candidate_tx.send(event.candidate);
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        let _ = self.gathering_tx.send(state);
    }
}

/// Signals every gathered local candidate to the remote connection.
fn spawn_candidate_forwarder<S: Signaling + 'static>(
    mut candidate_rx: mpsc::UnboundedReceiver<RTCIceCandidate>,
    signaling: Arc<S>,
    connection_id: u64,
    remote_network_id: String,
) {
    tokio::spawn(async move {
        let mut index = 0usize;
        while let Some(candidate) = candidate_rx.recv().await {
            let data = format_ice_candidate(index, &candidate, "");
            index += 1;
            if let Err(e) = signaling
                .signal(Signal::candidate(
                    connection_id,
                    data,
                    remote_network_id.clone(),
                ))
                .await
            {
                tracing::debug!("Failed to forward local ICE candidate: {}", e);
                break;
            }
        }
    });
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

/// NetherNet stream - data transmission over WebRTC
struct SessionStream {
    session: Arc<Session>,
    recv_future: ReusableBoxFuture<'static, Result<Option<Bytes>>>,
}

impl Stream for SessionStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.recv_future.poll(cx) {
            Poll::Ready(result) => {
                let session = self.session.clone();
                self.recv_future.set(async move { session.recv().await });
                match result {
                    Ok(Some(data)) => Poll::Ready(Some(Ok(data))),
                    Ok(None) => Poll::Ready(None),
                    Err(e) => Poll::Ready(Some(Err(io::Error::other(e)))),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// NetherNet stream - data transmission over WebRTC
pub struct NethernetStream {
    session: Arc<Session>,
    reader: StreamReader<SessionStream, Bytes>,
    send_future: Option<ReusableBoxFuture<'static, Result<()>>>,
    shutdown_future: Option<ReusableBoxFuture<'static, Result<()>>>,
}

impl NethernetStream {
    /// Establishes a NethernetStream with the remote network referenced by the ID.
    ///
    /// An offer is signaled with the local session description, and the answer signaled
    /// back by the remote connection completes the negotiation. Once the connection is
    /// established, the reliable and unreliable data channels are created and the stream
    /// is ready for send/recv operations.
    pub async fn connect<S: Signaling + 'static>(
        signaling: Arc<S>,
        remote_network_id: String,
    ) -> Result<Self> {
        Self::connect_with(signaling, remote_network_id, ConnectionConfig::default()).await
    }

    /// Establishes a NethernetStream using the timeouts of the given configuration.
    ///
    /// A negotiation that runs out of time is retried until the configured number of
    /// attempts is used up. Every attempt negotiates under a connection ID of its own,
    /// since a remote connection that answers the previous offer too late would answer an
    /// ID this side no longer waits for.
    pub async fn connect_with<S: Signaling + 'static>(
        signaling: Arc<S>,
        remote_network_id: String,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let attempts = config.attempts.max(1);

        for attempt in 1..=attempts {
            let mut connection_id_bytes = [0u8; 8];
            rand::rng().fill_bytes(&mut connection_id_bytes);
            let connection_id = u64::from_le_bytes(connection_id_bytes);

            let cancel_token = config.cancel_token.clone();
            let result = tokio::select! {
                _ = cancel_token.cancelled() => Err((None, NethernetError::ConnectionClosed)),
                result = Self::negotiate(
                    &signaling,
                    &remote_network_id,
                    connection_id,
                    config.clone(),
                ) => result,
            };

            let (code, error) = match result {
                Ok(stream) => return Ok(stream),
                Err(failure) => failure,
            };

            if let Some(code) = code {
                let _ = signaling
                    .signal(Signal::error(
                        connection_id,
                        code,
                        remote_network_id.clone(),
                    ))
                    .await;
            }

            // Anything else is an answer this side understood, so another offer changes nothing
            if !matches!(error, NethernetError::Timeout) || attempt == attempts {
                return Err(error);
            }

            tracing::debug!(
                "negotiation attempt {} of {} timed out, offering again",
                attempt,
                attempts
            );
        }

        Err(NethernetError::Timeout)
    }

    /// Negotiates the connection, reporting the error code to be signaled back to the
    /// remote connection when a step fails.
    async fn negotiate<S: Signaling + 'static>(
        signaling: &Arc<S>,
        remote_network_id: &str,
        connection_id: u64,
        config: ConnectionConfig,
    ) -> std::result::Result<Self, (Option<SignalErrorCode>, NethernetError)> {
        let (candidate_tx, candidate_rx) = mpsc::unbounded_channel();
        let (gathering_tx, gathering_rx) = mpsc::unbounded_channel();
        let handler = Arc::new(CandidateHandler {
            candidate_tx,
            gathering_tx,
        });

        let credentials = signaling
            .credentials()
            .await
            .map_err(|e| (Some(SignalErrorCode::SignalingTurnAuthFailed), e))?;
        let peer_connection = build_peer_connection(credentials.as_ref(), handler)
            .await
            .map_err(|e| (Some(SignalErrorCode::FailedToCreatePeerConnection), e))?;

        let reliable = peer_connection
            .create_data_channel(
                RELIABLE_CHANNEL,
                Some(RTCDataChannelInit {
                    ordered: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToCreatePeerConnection),
                    e.into(),
                )
            })?;
        let unreliable = peer_connection
            .create_data_channel(
                UNRELIABLE_CHANNEL,
                Some(RTCDataChannelInit {
                    max_retransmits: Some(0),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToCreatePeerConnection),
                    e.into(),
                )
            })?;

        let offer = peer_connection
            .create_offer(None)
            .await
            .map_err(|e| (Some(SignalErrorCode::FailedToCreateOffer), e.into()))?;
        peer_connection
            .set_local_description(offer.clone())
            .await
            .map_err(|e| (Some(SignalErrorCode::FailedToSetLocalDescription), e.into()))?;

        // Trickle connections signal every gathered candidate of their own
        let disable_trickle_ice = signaling.disable_trickle_ice();
        if !disable_trickle_ice {
            spawn_candidate_forwarder(
                candidate_rx,
                signaling.clone(),
                connection_id,
                remote_network_id.to_string(),
            );
        }

        // Non-trickle connections carry every local candidate in the offer itself
        let offer_sdp = if disable_trickle_ice {
            wait_for_gathering_complete(gathering_rx, config.timeouts.start)
                .await
                .map_err(|e| (Some(SignalErrorCode::FailedToCreateOffer), e))?;
            peer_connection
                .local_description()
                .await
                .ok_or((
                    Some(SignalErrorCode::FailedToCreateOffer),
                    NethernetError::InvalidState("missing local description".to_string()),
                ))?
                .sdp
        } else {
            offer.sdp
        };

        // A server that validates identities has nothing to accept without one
        let offer_sdp = match &config.identity {
            Some(identity) => identity.augment(&offer_sdp).map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToCreateOffer),
                    NethernetError::Identity(e),
                )
            })?,
            None => offer_sdp,
        };

        let mut signals = signaling.signals();

        signaling
            .signal(Signal::offer(
                connection_id,
                offer_sdp,
                remote_network_id.to_string(),
            ))
            .await
            .map_err(|e| (None, e))?;

        let mut pending_candidates = Vec::new();
        let answer = tokio::time::timeout(config.timeouts.negotiation, async {
            loop {
                let Some(signal) = signals.next().await else {
                    return Err((None, NethernetError::ConnectionClosed));
                };
                if signal.connection_id != connection_id || signal.network_id != remote_network_id {
                    continue;
                }
                match signal.signal_type {
                    SignalType::Answer => return Ok(signal.data),
                    SignalType::Candidate => match parse_ice_candidate(&signal.data) {
                        Ok(candidate) => pending_candidates.push(candidate),
                        Err(e) => tracing::warn!("Failed to parse remote candidate: {}", e),
                    },
                    SignalType::Error => {
                        let code = parse_error_code(&signal.data);
                        return Err((None, NethernetError::Signaled(code)));
                    }
                    SignalType::Offer => {
                        return Err((
                            Some(SignalErrorCode::IncomingConnectionIgnored),
                            NethernetError::Other("received offer while dialing".to_string()),
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            (
                Some(SignalErrorCode::NegotiationTimeoutWaitingForResponse),
                NethernetError::Timeout,
            )
        })??;

        let remote_description = RTCSessionDescription::answer(answer).map_err(|e| {
            (
                Some(SignalErrorCode::FailedToSetRemoteDescription),
                NethernetError::WebRtc(e),
            )
        })?;
        peer_connection
            .set_remote_description(remote_description)
            .await
            .map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToSetRemoteDescription),
                    NethernetError::WebRtc(e),
                )
            })?;
        for candidate in pending_candidates {
            if let Err(e) = peer_connection.add_ice_candidate(candidate).await {
                tracing::warn!("Failed to add remote candidate: {}", e);
            }
        }

        wait_for_channel_open(reliable.clone(), config.timeouts.start)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;
        wait_for_channel_open(unreliable.clone(), config.timeouts.start)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;

        let peer_for_signals = peer_connection.clone();
        let session = Arc::new(Session::new(
            peer_connection,
            Addr::new(signaling.network_id(), connection_id),
            Addr::new(remote_network_id.to_string(), connection_id),
        ));
        session
            .set_reliable_channel(reliable)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;
        session
            .set_unreliable_channel(unreliable)
            .await
            .map_err(|e| (Some(SignalErrorCode::Ice), e))?;

        let session_for_signals = session.clone();
        let remote_id = remote_network_id.to_string();
        tokio::spawn(async move {
            loop {
                let signal = tokio::select! {
                    _ = session_for_signals.closed() => break,
                    signal = signals.next() => match signal {
                        Some(signal) => signal,
                        None => break,
                    },
                };
                if signal.connection_id != connection_id || signal.network_id != remote_id {
                    continue;
                }
                match signal.signal_type {
                    SignalType::Candidate => match parse_ice_candidate(&signal.data) {
                        Ok(candidate) => {
                            if let Err(e) = peer_for_signals.add_ice_candidate(candidate).await {
                                tracing::warn!("Failed to add remote candidate: {}", e);
                            }
                        }
                        Err(e) => tracing::warn!("Failed to parse remote candidate: {}", e),
                    },
                    SignalType::Error => {
                        let code = parse_error_code(&signal.data);
                        tracing::debug!("Remote connection signaled an error: {:?}", code);
                        let _ = session_for_signals.close().await;
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(Self::from_session(session))
    }

    /// Constructs a NethernetStream from an existing Session.
    pub fn from_session(session: Arc<Session>) -> Self {
        let session_clone = session.clone();
        let recv_future = ReusableBoxFuture::new(async move { session_clone.recv().await });

        let stream = SessionStream {
            session: session.clone(),
            recv_future,
        };

        Self {
            session,
            reader: StreamReader::new(stream),
            send_future: None,
            shutdown_future: None,
        }
    }

    /// Transmits a payload to the remote endpoint associated with this stream.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.session.send(data).await
    }

    /// Transmits a payload over the unreliable data channel of this stream.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        self.session.send_unreliable(data).await
    }

    /// Receive the next available data frame from the unreliable data channel.
    pub async fn recv_unreliable(&self) -> Result<Option<Bytes>> {
        self.session.recv_unreliable().await
    }

    /// Receive the next available data frame from this stream.
    pub async fn recv(&self) -> Result<Option<Bytes>> {
        self.session.recv().await
    }

    /// Close the stream and its underlying session.
    pub async fn close(&self) -> Result<()> {
        self.session.close().await
    }

    /// Get the address of the remote endpoint for this stream.
    pub async fn remote_addr(&self) -> Addr {
        self.session.remote_addr().await
    }

    /// Get the local address of this stream.
    pub async fn local_addr(&self) -> Addr {
        self.session.local_addr().await
    }

    /// Access the underlying session.
    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }
}

impl AsyncRead for NethernetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for NethernetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If there's an active send future, poll it first
        if let Some(mut fut) = self.send_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {
                    // Previous send completed
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => {
                    // Still sending
                    self.send_future = Some(fut);
                    return Poll::Pending;
                }
            }
        }

        // Start new send
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        let session = self.session.clone();
        let mut fut = ReusableBoxFuture::new(async move { session.send(data).await });

        // Poll immediately to start the future
        match fut.poll(cx) {
            Poll::Ready(Ok(())) => {
                // Completed immediately
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e)));
            }
            Poll::Pending => {
                self.send_future = Some(fut);
            }
        }

        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(mut fut) = self.send_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => {
                    self.send_future = Some(fut);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First flush any pending writes
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if self.shutdown_future.is_none() {
            let session = self.session.clone();
            self.shutdown_future =
                Some(ReusableBoxFuture::new(async move { session.close().await }));
        }

        if let Some(mut fut) = self.shutdown_future.take() {
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => {
                    self.shutdown_future = Some(fut);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

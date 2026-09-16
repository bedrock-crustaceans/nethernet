use crate::addr::Addr;
use crate::error::{NethernetError, Result, SignalErrorCode};
use crate::protocol::{Signal, SignalType};
use crate::session::{Command, Session};
use crate::signaling::Signaling;
use crate::transport::{ConnectionConfig, local_bind_addr};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use nethernet::connection::{Connection as SansConnection, IceMode};
use nethernet::session::Session as SansSession;
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio_util::io::StreamReader;
use tokio_util::sync::ReusableBoxFuture;

/// Parses the error code of a `CONNECTERROR` signal.
pub(crate) fn parse_error_code(data: &str) -> SignalErrorCode {
    data.trim().parse::<u32>().map_or(
        SignalErrorCode::SignalingUnknownError,
        SignalErrorCode::from,
    )
}

/// Keeps forwarding further signals for `(remote_network_id, connection_id)` into the
/// now-running connection, until either the signal stream ends or the connection stops
/// (which drops the driver's command receiver, so `command_tx.send` starts failing).
fn spawn_late_signal_forwarder<St>(
    mut signals: St,
    connection_id: u64,
    remote_network_id: String,
    command_tx: tokio::sync::mpsc::UnboundedSender<Command>,
) where
    St: Stream<Item = Signal> + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            if signal.connection_id != connection_id || signal.network_id != remote_network_id {
                continue;
            }
            if signal.signal_type != SignalType::Candidate {
                continue;
            }
            if command_tx.send(Command::Signal(signal)).is_err() {
                break;
            }
        }
    });
}

/// NetherNet stream - data transmission over a NetherNet session.
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

/// NetherNet stream - data transmission over a NetherNet session.
pub struct NethernetStream {
    session: Arc<Session>,
    reader: StreamReader<SessionStream, Bytes>,
    send_future: Option<ReusableBoxFuture<'static, Result<()>>>,
    shutdown_future: Option<ReusableBoxFuture<'static, Result<()>>>,
}

impl NethernetStream {
    /// Establishes a NethernetStream with the remote network referenced by the ID.
    ///
    /// An offer is signaled with the parameters of a freshly created session, and the
    /// answer signaled back by the remote connection is used to complete the connection.
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
        let socket = Arc::new(
            UdpSocket::bind(local_bind_addr())
                .await
                .map_err(|e| (None, NethernetError::from(e)))?,
        );
        let bound_addr = socket
            .local_addr()
            .map_err(|e| (None, NethernetError::from(e)))?;

        let (session, description) = SansSession::new(bound_addr, true).map_err(|e| {
            (
                Some(SignalErrorCode::FailedToCreatePeerConnection),
                NethernetError::from(e),
            )
        })?;

        let ice_mode = if signaling.disable_trickle_ice() {
            IceMode::Full
        } else {
            IceMode::Trickle
        };

        let (mut connection, signals) = SansConnection::connect(
            session,
            description,
            connection_id,
            remote_network_id.to_string(),
            ice_mode,
        );

        let mut signals_out = signals.into_iter();
        let offer = signals_out
            .next()
            .expect("Connection::connect always returns an offer signal first");

        // A server that validates identities has nothing to accept without one
        let offer_data = match &config.identity {
            Some(identity) => identity.augment(&offer.data).map_err(|e| {
                (
                    Some(SignalErrorCode::FailedToCreateOffer),
                    NethernetError::Identity(e),
                )
            })?,
            None => offer.data,
        };

        let mut signals = signaling.signals();

        signaling
            .signal(Signal::offer(
                connection_id,
                offer_data,
                remote_network_id.to_string(),
            ))
            .await
            .map_err(|e| (None, e))?;
        for trickled in signals_out {
            signaling.signal(trickled).await.map_err(|e| (None, e))?;
        }

        // Under trickle ICE, the answer and its trailing candidate are two separate
        // signals that can arrive in either order, and the session only starts DTLS/SCTP
        // once *both* the remote description and a remote candidate have been applied -
        // so both are awaited here (under full ICE, the candidate is embedded in the
        // answer's SDP itself, so there is nothing further to wait for).
        let mut need_candidate = ice_mode == IceMode::Trickle;
        let deadline = tokio::time::Instant::now() + config.timeouts.negotiation;

        loop {
            let signal = tokio::time::timeout_at(deadline, async {
                loop {
                    let signal = signals.next().await?;
                    if signal.connection_id == connection_id
                        && signal.network_id == remote_network_id
                    {
                        return Some(signal);
                    }
                }
            })
            .await
            .map_err(|_| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForResponse),
                    NethernetError::Timeout,
                )
            })?
            .ok_or((None, NethernetError::ConnectionClosed))?;

            match signal.signal_type {
                SignalType::Answer => {
                    connection.handle_signal(&signal).map_err(|e| {
                        (
                            Some(SignalErrorCode::FailedToSetRemoteDescription),
                            NethernetError::from(e),
                        )
                    })?;
                    if !need_candidate {
                        break;
                    }
                }
                SignalType::Candidate => {
                    connection
                        .handle_signal(&signal)
                        .map_err(|e| (Some(SignalErrorCode::Ice), NethernetError::from(e)))?;
                    need_candidate = false;
                }
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

            if connection.remote_addr().is_some() && !need_candidate {
                break;
            }
        }

        let local = Addr::new(signaling.network_id(), connection_id);
        let remote = Addr::new(remote_network_id.to_string(), connection_id);

        let (session, ready_rx) = Session::spawn(socket, connection, local, remote);
        let session = Arc::new(session);

        spawn_late_signal_forwarder(
            signals,
            connection_id,
            remote_network_id.to_string(),
            session.signal_sender(),
        );

        tokio::time::timeout(config.timeouts.start + config.timeouts.channel, ready_rx)
            .await
            .map_err(|_| {
                (
                    Some(SignalErrorCode::NegotiationTimeoutWaitingForAccept),
                    NethernetError::Timeout,
                )
            })?
            .map_err(|_| (None, NethernetError::ConnectionClosed))?;

        Ok(Self::from_session(session))
    }

    /// Constructs a NethernetStream from an existing Session.
    pub(crate) fn from_session(session: Arc<Session>) -> Self {
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

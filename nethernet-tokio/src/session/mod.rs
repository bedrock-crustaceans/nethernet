use crate::addr::Addr;
use crate::error::{NethernetError, Result};
use crate::protocol::constants::DEFAULT_PACKET_CHANNEL_CAPACITY;
use crate::protocol::{Message, MessageSegment};
use bytes::{Bytes, BytesMut};
use nethernet::identity::PlayerInfo;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::PeerConnection;

/// Routes the message segments received on the channel into the buffer, forwarding
/// each reassembled message to the receiver.
fn spawn_channel_reader(
    channel: Arc<dyn DataChannel>,
    buffer: Arc<Mutex<Message>>,
    tx: mpsc::Sender<Bytes>,
) {
    tokio::spawn(async move {
        while let Some(event) = channel.poll().await {
            let DataChannelEvent::OnMessage(message) = event else {
                continue;
            };
            let data = message.data.freeze();
            let data_len = data.len();
            match MessageSegment::decode(data.clone()) {
                Ok(segment) => {
                    let result = {
                        let mut buffer = buffer.lock().await;
                        buffer.add_segment(segment)
                    };
                    match result {
                        Ok(Some(complete_message)) => {
                            // If send fails, the receiver has been dropped
                            let _ = tx.send(complete_message).await;
                        }
                        Ok(None) => {
                            tracing::debug!(
                                "incomplete segment added to buffer, waiting for more segments"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                "failed to add segment to buffer: {:?}, data length: {}",
                                error,
                                data_len
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        "failed to decode message segment: {:?}, data length: {}",
                        error,
                        data_len
                    );
                }
            }
        }
    });
}

/// WebRTC session manager
pub struct Session {
    peer_connection: Arc<dyn PeerConnection>,
    local: Addr,
    remote: Arc<Mutex<Addr>>,
    reliable_channel: StdRwLock<Option<Arc<dyn DataChannel>>>,
    unreliable_channel: StdRwLock<Option<Arc<dyn DataChannel>>>,
    message_buffer: Arc<Mutex<Message>>,
    unreliable_buffer: Arc<Mutex<Message>>,
    packet_tx: mpsc::Sender<Bytes>,
    packet_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    unreliable_tx: mpsc::Sender<Bytes>,
    unreliable_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    closed: AtomicBool,
    close_token: CancellationToken,
    player: Arc<RwLock<Option<Arc<PlayerInfo>>>>,
}

impl Session {
    /// Creates a Session using the default packet channel capacity.
    pub fn new(peer_connection: Arc<dyn PeerConnection>, local: Addr, remote: Addr) -> Self {
        Self::with_capacity(
            peer_connection,
            local,
            remote,
            DEFAULT_PACKET_CHANNEL_CAPACITY,
        )
    }

    /// Creates a Session backed by the given peer connection and a bounded packet
    /// channel with the specified capacity.
    ///
    /// The local address holds the locally gathered candidates, while the remote address
    /// is extended with the candidates signaled by the remote connection.
    pub fn with_capacity(
        peer_connection: Arc<dyn PeerConnection>,
        local: Addr,
        remote: Addr,
        capacity: usize,
    ) -> Self {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);
        let (unreliable_tx, unreliable_rx) = mpsc::channel(capacity);

        Self {
            peer_connection,
            local,
            remote: Arc::new(Mutex::new(remote)),
            reliable_channel: StdRwLock::new(None),
            unreliable_channel: StdRwLock::new(None),
            message_buffer: Arc::new(Mutex::new(Message::new())),
            unreliable_buffer: Arc::new(Mutex::new(Message::new())),
            packet_tx,
            packet_rx: Arc::new(Mutex::new(packet_rx)),
            unreliable_tx,
            unreliable_rx: Arc::new(Mutex::new(unreliable_rx)),
            closed: AtomicBool::new(false),
            close_token: CancellationToken::new(),
            player: Arc::new(RwLock::new(None)),
        }
    }

    /// Attaches the reliable data channel to the session and routes incoming message
    /// segments into the session's reassembly pipeline.
    pub async fn set_reliable_channel(&self, channel: Arc<dyn DataChannel>) -> Result<()> {
        spawn_channel_reader(
            channel.clone(),
            self.message_buffer.clone(),
            self.packet_tx.clone(),
        );
        *self
            .reliable_channel
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(channel);
        Ok(())
    }

    /// Attaches the unreliable data channel to the session and routes incoming
    /// message segments into a separate reassembly pipeline.
    pub async fn set_unreliable_channel(&self, channel: Arc<dyn DataChannel>) -> Result<()> {
        spawn_channel_reader(
            channel.clone(),
            self.unreliable_buffer.clone(),
            self.unreliable_tx.clone(),
        );
        *self
            .unreliable_channel
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(channel);
        Ok(())
    }

    /// Sends data over the session using the reliable data channel, splitting the
    /// payload into protocol segments as needed.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(NethernetError::ConnectionClosed);
        }

        let channel = self
            .reliable_channel
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| NethernetError::DataChannel("Reliable channel not set".to_string()))?;
        for segment in Message::split_into_segments(data)? {
            channel
                .send(BytesMut::from(segment.encode().as_ref()))
                .await
                .map_err(|e| NethernetError::DataChannel(e.to_string()))?;
        }

        Ok(())
    }

    /// Sends data over the session using the unreliable data channel.
    ///
    /// Data sent over a channel that was opened out of band is dropped by remote
    /// connections that did not open the matching channel themselves.
    pub async fn send_unreliable(&self, data: Bytes) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(NethernetError::ConnectionClosed);
        }

        let channel = self
            .unreliable_channel
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| NethernetError::DataChannel("Unreliable channel not set".to_string()))?;
        for segment in Message::split_into_segments(data)? {
            channel
                .send(BytesMut::from(segment.encode().as_ref()))
                .await
                .map_err(|e| NethernetError::DataChannel(e.to_string()))?;
        }

        Ok(())
    }

    /// Receives the next complete packet from the unreliable data channel.
    ///
    /// Returns `Ok(None)` once the session has been closed.
    pub async fn recv_unreliable(&self) -> Result<Option<Bytes>> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(None);
        }

        Ok(self.unreliable_rx.lock().await.recv().await)
    }

    /// Receives the next complete packet from the session.
    ///
    /// This returns the next reassembled message produced by the session's incoming
    /// segment stream. If the session has been closed, or the underlying packet
    /// channel has been closed, this returns `Ok(None)`.
    pub async fn recv(&self) -> Result<Option<Bytes>> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(None);
        }

        Ok(self.packet_rx.lock().await.recv().await)
    }

    /// Shuts down the session by marking it closed and closing any attached data
    /// channels and the peer connection.
    ///
    /// After this call the session is considered closed; calling `close` again is a no-op.
    pub async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.close_token.cancel();

        let reliable = self
            .reliable_channel
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(channel) = reliable {
            let _ = channel.close().await;
        }

        let unreliable = self
            .unreliable_channel
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(channel) = unreliable {
            let _ = channel.close().await;
        }

        self.peer_connection
            .close()
            .await
            .map_err(NethernetError::from)
    }

    /// Returns the local address of the session.
    pub async fn local_addr(&self) -> Addr {
        self.local.clone()
    }

    /// Returns the address of the remote connection, including the candidates it has
    /// signaled.
    pub async fn remote_addr(&self) -> Addr {
        self.remote.lock().await.clone()
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
        self.closed.load(Ordering::Acquire)
    }
}

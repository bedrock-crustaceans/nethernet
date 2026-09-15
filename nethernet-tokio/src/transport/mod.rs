pub mod listener;
pub mod stream;

pub use listener::NethernetListener;
pub use stream::NethernetStream;

use crate::credentials::Credentials;
use crate::error::{NethernetError, Result};
use nethernet::identity::{ServerIdentity, TokenTrust};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceServer,
};

/// Options applied while negotiating and establishing a connection.
#[derive(Clone)]
pub struct ConnectionConfig {
    /// Timeouts of each negotiation step.
    pub timeouts: Timeouts,

    /// Cancels the negotiation when triggered. Connections that are already established
    /// are unaffected, as they are closed through the session itself.
    pub cancel_token: CancellationToken,

    /// How many times a connection is negotiated before dialing gives up.
    ///
    /// A negotiation that times out is retried under a new connection ID, since a peer
    /// that missed the first offer has nothing to answer and one that answered too late
    /// would answer an ID this side no longer waits for.
    pub attempts: u32,

    /// The identity answers are signed with, or [`None`] to answer without one.
    ///
    /// A client pins the key of a server, so it should be kept between restarts rather
    /// than generated on each start.
    pub identity: Option<Arc<ServerIdentity>>,

    /// Who is trusted to have signed the token of an offer, or [`None`] to accept offers
    /// without validating the identity they carry.
    pub token_trust: Option<TokenTrust>,

    /// Whether the address a peer signaled from is checked when its offer holds nothing
    /// routable. It does nothing for a peer that gathered a routable candidate itself.
    pub infer_peer_candidates: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            cancel_token: CancellationToken::new(),
            attempts: 3,
            identity: None,
            token_trust: None,
            infer_peer_candidates: true,
        }
    }
}

impl fmt::Debug for ConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionConfig")
            .field("timeouts", &self.timeouts)
            .field("attempts", &self.attempts)
            .field("identity", &self.identity.is_some())
            .field("token_trust", &self.token_trust.is_some())
            .field("infer_peer_candidates", &self.infer_peer_candidates)
            .finish()
    }
}

/// Timeouts applied while negotiating and establishing a connection.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Time to wait for the answer of the remote connection. Only used while dialing.
    pub negotiation: Duration,

    /// Time to wait for the first candidate signaled by the remote connection.
    pub candidate: Duration,

    /// Time to wait for each transport to start.
    pub start: Duration,

    /// Time to wait for the data channels created by the remote connection. Only used
    /// while listening, as the dialing side creates them itself.
    pub channel: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            negotiation: Duration::from_secs(15),
            candidate: Duration::from_secs(5),
            start: Duration::from_secs(5),
            channel: Duration::from_secs(5),
        }
    }
}

/// Builds a peer connection using the credentials returned by signaling.
pub(crate) async fn build_peer_connection(
    credentials: Option<&Credentials>,
    handler: Arc<dyn PeerConnectionEventHandler>,
) -> Result<Arc<dyn PeerConnection>> {
    let ice_servers = credentials
        .into_iter()
        .flat_map(|credentials| credentials.ice_servers.iter())
        .map(|server| RTCIceServer {
            urls: server.urls.clone(),
            username: server.username.clone(),
            credential: server.password.clone(),
        })
        .collect();

    let configuration = RTCConfigurationBuilder::new()
        .with_ice_servers(ice_servers)
        .build();
    let peer_connection = PeerConnectionBuilder::new()
        .with_configuration(configuration)
        .with_handler(handler)
        .with_udp_addrs(vec!["0.0.0.0:0"])
        .build()
        .await
        .map_err(NethernetError::from)?;

    Ok(Arc::new(peer_connection))
}

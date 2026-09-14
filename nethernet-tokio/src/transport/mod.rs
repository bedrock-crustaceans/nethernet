pub mod listener;
pub mod stream;

pub use listener::NethernetListener;
pub use stream::NethernetStream;

use crate::credentials::{Credentials, gather_options};
use crate::error::{NethernetError, Result};
use crate::protocol::constants::SCTP_MAX_MESSAGE_SIZE;
use crate::protocol::webrtc::Description;
use nethernet::identity::{ServerIdentity, TokenTrust};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{API, APIBuilder};
use webrtc::dtls_transport::RTCDtlsTransport;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice_transport::RTCIceTransport;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_gatherer::RTCIceGatherer;
use webrtc::ice_transport::ice_parameters::RTCIceParameters;
use webrtc::sctp_transport::RTCSctpTransport;
use webrtc::sctp_transport::sctp_transport_capabilities::SCTPTransportCapabilities;

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

/// The transports backing a single connection.
///
/// NetherNet does not use a peer connection, as it does not allow signaling a session
/// description with the exact layout expected by vanilla clients. The transports are
/// therefore created and started directly.
pub(crate) struct Transports {
    pub(crate) api: API,
    pub(crate) gatherer: Arc<RTCIceGatherer>,
    pub(crate) ice: Arc<RTCIceTransport>,
    pub(crate) dtls: Arc<RTCDtlsTransport>,
    pub(crate) sctp: Arc<RTCSctpTransport>,
}

impl Transports {
    pub(crate) fn new(
        setting_engine: SettingEngine,
        credentials: Option<&Credentials>,
    ) -> Result<Self> {
        let api = APIBuilder::new()
            .with_media_engine(MediaEngine::default())
            .with_setting_engine(setting_engine)
            .build();

        let gatherer = Arc::new(api.new_ice_gatherer(gather_options(credentials))?);
        let ice = Arc::new(api.new_ice_transport(gatherer.clone()));
        let dtls = Arc::new(api.new_dtls_transport(ice.clone(), vec![])?);
        let sctp = Arc::new(api.new_sctp_transport(dtls.clone())?);

        Ok(Self {
            api,
            gatherer,
            ice,
            dtls,
            sctp,
        })
    }

    /// Gathers the local candidates and returns them along with the local ICE parameters.
    pub(crate) async fn gather(&self) -> Result<(Vec<RTCIceCandidate>, RTCIceParameters)> {
        let (finished_tx, finished_rx) = oneshot::channel();
        let finished_tx = Arc::new(tokio::sync::Mutex::new(Some(finished_tx)));

        self.gatherer
            .on_local_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
                let finished_tx = finished_tx.clone();
                Box::pin(async move {
                    if candidate.is_none()
                        && let Some(tx) = finished_tx.lock().await.take()
                    {
                        let _ = tx.send(());
                    }
                })
            }));

        self.gatherer.gather().await?;
        let _ = finished_rx.await;

        Ok((
            self.gatherer.get_local_candidates().await?,
            self.gatherer.get_local_parameters().await?,
        ))
    }

    /// Builds the description to be signaled as an offer or an answer. The DTLS role is
    /// the role the local connection announces, not the role it ends up acting as.
    pub(crate) fn local_description(
        &self,
        ice: RTCIceParameters,
        role: DTLSRole,
        candidates: Vec<RTCIceCandidate>,
    ) -> Result<Description> {
        let mut dtls = self.dtls.get_local_parameters()?;
        if dtls.fingerprints.is_empty() {
            return Err(NethernetError::Dtls(
                "local DTLS parameters have no fingerprints".to_string(),
            ));
        }
        dtls.role = role;

        Ok(Description {
            ice,
            dtls,
            sctp: SCTPTransportCapabilities {
                max_message_size: SCTP_MAX_MESSAGE_SIZE,
            },
            candidates,
        })
    }
}

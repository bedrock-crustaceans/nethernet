//! Client and server connections over a signaling backend.
pub mod client;
pub mod server;

pub use client::NetherClient;
pub use nethernet::connection::Timeouts;
pub use server::NetherServer;

use nethernet::identity::{ServerIdentity, TokenTrust};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub(crate) fn local_bind_addr() -> SocketAddr {
    let probe = || -> std::io::Result<IpAddr> {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr().map(|addr| addr.ip())
    };

    SocketAddr::new(probe().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
}
use tokio_util::sync::CancellationToken;

/// Settings shared by NetherClient::connect_with and NetherServer::bind_with.
#[derive(Clone)]
pub struct ConnectionConfig {
    /// Deadlines for the stages of negotiation.
    pub timeouts: Timeouts,

    /// Aborts client negotiation when cancelled.
    pub cancel_token: CancellationToken,

    /// Client offers made when negotiation times out; 0 counts as 1.
    pub attempts: u32,

    /// Server identity that signs answers; HTTP signaling needs it unless allow_unsigned_answers is set.
    pub identity: Option<Arc<ServerIdentity>>,

    /// Answers without a signature, which the vanilla client refuses (guide section 5.2).
    pub allow_unsigned_answers: bool,

    /// How the server authenticates offers; None skips validation.
    pub token_trust: Option<TokenTrust>,

    /// Adds candidates from the signaling source address when an offer has no routable host candidate.
    pub infer_peer_candidates: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            cancel_token: CancellationToken::new(),
            attempts: 3,
            identity: None,
            allow_unsigned_answers: false,
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
            .field("allow_unsigned_answers", &self.allow_unsigned_answers)
            .field("token_trust", &self.token_trust.is_some())
            .field("infer_peer_candidates", &self.infer_peer_candidates)
            .finish()
    }
}

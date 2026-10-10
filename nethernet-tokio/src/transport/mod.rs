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

#[derive(Clone)]
pub struct ConnectionConfig {
    pub timeouts: Timeouts,

    pub cancel_token: CancellationToken,

    pub attempts: u32,

    pub identity: Option<Arc<ServerIdentity>>,

    pub allow_unsigned_answers: bool,

    pub token_trust: Option<TokenTrust>,

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

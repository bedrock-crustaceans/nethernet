pub mod listener;
pub mod stream;

pub use listener::NethernetListener;
pub use stream::NethernetStream;

use nethernet::identity::{ServerIdentity, TokenTrust};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Picks the local address a per-connection UDP socket binds to.
///
/// NetherNet's session engine gathers exactly one UDP host candidate, at whatever
/// address its socket is bound to (see `nethernet::session::ice`) - unlike a generic
/// WebRTC stack, it does not enumerate every local interface itself. Binding to
/// `0.0.0.0` would advertise that literal (unroutable) address as the candidate, so a
/// real local address is picked instead: the one the OS would route a packet to a
/// public address through, which is also a reasonable guess for which interface a peer
/// can actually reach. Falls back to loopback if that fails (e.g. no network is up),
/// which still works for same-host signaling such as LAN discovery over loopback.
pub(crate) fn local_bind_addr() -> SocketAddr {
    let probe = || -> std::io::Result<IpAddr> {
        // A UDP "connect" performs no I/O of its own; it only asks the OS to pick the
        // local address that would be used to route to the given (unreached) remote.
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr().map(|addr| addr.ip())
    };

    SocketAddr::new(probe().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
}
use tokio_util::sync::CancellationToken;

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

    /// Time to wait for the transport (ICE/DTLS) to start. Added to `channel` for the
    /// total post-negotiation budget, since there's no separate signal to time the two
    /// phases apart.
    pub start: Duration,

    /// Time to wait for the data channels to open, once transports have started.
    pub channel: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            negotiation: Duration::from_secs(15),
            start: Duration::from_secs(5),
            channel: Duration::from_secs(5),
        }
    }
}

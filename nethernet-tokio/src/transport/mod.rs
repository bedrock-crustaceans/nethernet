pub mod client;
pub mod server;

pub use client::NetherClient;
pub use nethernet::connection::Timeouts;
pub use server::NetherServer;

use nethernet::identity::{ServerIdentity, TokenTrust};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

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
    /// A server over HTTP signaling must have one by default: `NetherServer::bind_with`
    /// fails with `NetherError::IdentityRequired` otherwise, unless
    /// [`allow_unsigned_answers`](Self::allow_unsigned_answers) opts out. Over LAN
    /// discovery it stays optional.
    ///
    /// A real Minecraft client refuses every connection whose answer lacks an
    /// `a=identity` assertion, over HTTP signaling or otherwise (see the NetherNet HTTP
    /// signaling guide, section 5.2). A client pins the key of a server, so it should be
    /// kept between restarts rather than generated on each start.
    pub identity: Option<Arc<ServerIdentity>>,

    /// Whether a server over HTTP signaling may run without an identity.
    ///
    /// Vanilla Minecraft clients refuse unsigned answers (NetherNet HTTP signaling guide,
    /// section 5.2), so enable this only for a server that serves non-vanilla clients.
    /// It does nothing when [`identity`](Self::identity) is set: answers are signed then.
    pub allow_unsigned_answers: bool,

    /// Who is trusted to have signed the token of an offer, or [`None`] to accept offers
    /// without validating the identity they carry.
    ///
    /// It applies only to offers arriving over signaling that does not validate them
    /// itself, which is LAN discovery. Offers over HTTP are validated by the signaler
    /// alone, through `HttpSignalerConfig::token_trust`, and this is ignored for them.
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

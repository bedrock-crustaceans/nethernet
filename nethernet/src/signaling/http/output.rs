//! Outputs of the HTTP endpoint state machine.

use crate::identity::PlayerInfo;
use http::Response;
use std::net::SocketAddr;
use std::time::Duration;

/// An offer that is waiting for the transport to answer it.
#[derive(Debug, Clone)]
pub struct Offer {
    /// The ID the answer has to name.
    pub connection_id: u64,

    /// The network ID of the peer, taken from the path of the request.
    pub network_id: String,

    /// The offer to negotiate against.
    pub sdp: String,

    /// The address the offer was signaled from, which seeds the connection before ICE
    /// settles and is what candidates are inferred from.
    pub client_address: Option<SocketAddr>,

    /// The host the peer asked for, for hosts that answer for more than one.
    pub host: Option<String>,

    /// The validated identity of the peer, or [`None`] when identities are not validated.
    pub player: Option<Box<PlayerInfo>>,
}

#[derive(Debug, Clone)]
pub enum HttpSignalerOutput {
    /// A response to write back on the connection.
    ///
    /// Closing a connection the peer still believes is open leaves its next request
    /// unanswered, so a response that does not keep the connection says so itself.
    Response {
        connection: u64,
        response: Box<Response<String>>,
        keep_alive: bool,
    },

    /// A connection to close without answering, which is what a peer over the limit gets.
    Close(u64),

    /// An offer the transport has to answer.
    Offer(Box<Offer>),

    /// How long the caller may wait before it has to drive the state machine again.
    Wait(Duration),
}

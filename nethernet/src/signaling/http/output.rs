//! Outputs produced by the HTTP signaler.
use crate::identity::PlayerInfo;
use crate::protocol::Signal;
use http::Response;
use std::net::SocketAddr;
use std::time::Duration;

/// A join waiting for an answer or rejection under `connection_id`.
#[derive(Debug, Clone)]
pub struct Offer {
    /// Random id for this join, used to answer or reject it.
    pub connection_id: u64,

    pub network_id: String,

    pub sdp: String,

    /// The peer address, or the first `x-forwarded-for` entry when the peer is a trusted proxy.
    pub client_address: Option<SocketAddr>,

    pub host: Option<String>,

    /// Set when token trust is configured.
    pub player: Option<Box<PlayerInfo>>,
}

impl Offer {
    pub fn signal(&self) -> Signal {
        Signal::offer(
            self.connection_id,
            self.sdp.clone(),
            self.network_id.clone(),
        )
    }
}

#[derive(Debug, Clone)]
pub enum HttpSignalerOutput {
    Response {
        connection: u64,
        response: Box<Response<String>>,
        keep_alive: bool,
    },

    Close(u64),

    Offer(Box<Offer>),

    /// Feed `Update` no later than this long from now.
    Wait(Duration),
}

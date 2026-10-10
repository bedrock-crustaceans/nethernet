use crate::identity::PlayerInfo;
use crate::protocol::Signal;
use http::Response;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Offer {
    pub connection_id: u64,

    pub network_id: String,

    pub sdp: String,

    pub client_address: Option<SocketAddr>,

    pub host: Option<String>,

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

    Wait(Duration),
}

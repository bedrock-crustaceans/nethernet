use crate::protocol::Signal;
use crate::protocol::packet::discovery::ServerData;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum LanSignalerInput {
    Datagram(Box<[u8]>, SocketAddr, Instant),

    Signal(Signal, Instant),

    SetServerData(Box<ServerData>),

    Update(Instant),
}

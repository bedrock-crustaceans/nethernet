use crate::protocol::Signal;
use crate::protocol::packet::discovery::ServerData;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum LanSignalerOutput {
    Datagram(Box<[u8]>, SocketAddr),

    Signal(Signal),

    ServerDiscovered(u64, Box<ServerData>),

    Wait(Duration),
}

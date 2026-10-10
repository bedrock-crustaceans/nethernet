//! Outputs produced by the LAN signaler.
use crate::protocol::Signal;
use crate::protocol::packet::discovery::ServerData;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum LanSignalerOutput {
    Datagram(Box<[u8]>, SocketAddr),

    Signal(Signal),

    /// A peer answered a discovery request with its server data.
    ServerDiscovered(u64, Box<ServerData>),

    /// Feed `Update` no later than this long from now.
    Wait(Duration),
}

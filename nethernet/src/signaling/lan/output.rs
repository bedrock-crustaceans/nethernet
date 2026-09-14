//! Outputs of the LAN discovery state machine.

use crate::protocol::Signal;
use crate::protocol::packet::discovery::ServerData;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum LanSignalerOutput {
    /// A datagram to write to the discovery socket.
    Datagram(Box<[u8]>, SocketAddr),

    /// A signal addressed to the local network.
    Signal(Signal),

    /// The data a remote network answered a discovery request with.
    ServerDiscovered(u64, Box<ServerData>),

    /// How long the caller may wait before it has to drive the state machine again.
    Wait(Duration),
}

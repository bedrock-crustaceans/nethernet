//! Inputs of the LAN discovery state machine.

use crate::protocol::Signal;
use crate::protocol::packet::discovery::ServerData;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum LanSignalerInput {
    /// A datagram received on the discovery socket.
    Datagram(Box<[u8]>, SocketAddr, Instant),

    /// A signal to deliver to the network it names.
    Signal(Signal, Instant),

    /// The data advertised in response to discovery requests.
    SetServerData(Box<ServerData>),

    /// Drives the broadcasts, the retransmissions and the expiry of known addresses.
    Update(Instant),
}

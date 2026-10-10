//! Inputs accepted by the LAN signaler.
use crate::protocol::Signal;
use crate::protocol::packet::discovery::ServerData;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum LanSignalerInput {
    Datagram(Box<[u8]>, SocketAddr, Instant),

    /// Sends a signal whose `network_id` is the target's id in decimal; it repeats until the target replies on that connection.
    Signal(Signal, Instant),

    SetServerData(Box<ServerData>),

    Update(Instant),
}

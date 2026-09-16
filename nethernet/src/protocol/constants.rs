//! Constants for the NetherNet discovery protocol.

/// Default UDP port used for LAN discovery.
pub const LAN_DISCOVERY_PORT: u16 = 7551;

pub const ID_REQUEST_PACKET: u16 = 0;
pub const ID_RESPONSE_PACKET: u16 = 1;
pub const ID_MESSAGE_PACKET: u16 = 2;

pub const MAX_MESSAGE_SIZE: usize = 10000;

/// Upper bound on general byte arrays, checked before allocating, to prevent OOM
/// attacks from a claimed length.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

/// PacketID (2) + SenderID (8) + Padding (8)
pub const HEADER_SIZE: usize = 18;

/// SCTP port announced in session descriptions.
pub const SCTP_PORT: u16 = 5000;

/// Maximum SCTP message size announced in session descriptions.
pub const SCTP_MAX_MESSAGE_SIZE: u32 = 65536;

pub const RELIABLE_CHANNEL: &str = "ReliableDataChannel";
pub const UNRELIABLE_CHANNEL: &str = "UnreliableDataChannel";

/// Default capacity for the bounded packet channel in sessions.
pub const DEFAULT_PACKET_CHANNEL_CAPACITY: usize = 1024;

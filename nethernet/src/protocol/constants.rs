//! Protocol constants.
/// UDP port LAN discovery uses by default.
pub const LAN_DISCOVERY_PORT: u16 = 7551;

pub const ID_REQUEST_PACKET: u16 = 0;
pub const ID_RESPONSE_PACKET: u16 = 1;
pub const ID_MESSAGE_PACKET: u16 = 2;

/// Payload bytes in one data-channel segment.
pub const MAX_MESSAGE_SIZE: usize = 10000;

/// Cap on any u32-length-prefixed field read or written by the codec.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

pub const HEADER_SIZE: usize = 18;

pub const SCTP_PORT: u16 = 5000;

/// `max-message-size` assumed when the remote SDP omits it.
pub const SCTP_MAX_MESSAGE_SIZE: u32 = 65536;

/// Labels of the two data channels NetherNet always opens (guide section 6).
pub const RELIABLE_CHANNEL: &str = "ReliableDataChannel";
pub const UNRELIABLE_CHANNEL: &str = "UnreliableDataChannel";

pub const DEFAULT_PACKET_CHANNEL_CAPACITY: usize = 1024;

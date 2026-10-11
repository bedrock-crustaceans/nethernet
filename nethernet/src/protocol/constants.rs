//! Protocol constants.
/// UDP port LAN discovery uses by default.
pub const LAN_DISCOVERY_PORT: u16 = 7551;

/// Receive buffer for discovery datagrams: the largest UDP payload.
pub const MAX_DATAGRAM_SIZE: usize = 65535;

pub const ID_REQUEST_PACKET: u16 = 0;
pub const ID_RESPONSE_PACKET: u16 = 1;
pub const ID_MESSAGE_PACKET: u16 = 2;

/// Payload bytes in one data-channel segment.
pub const MAX_MESSAGE_SIZE: usize = 10000;

/// Cap on any u32-length-prefixed field read or written by the codec.
pub const MAX_BYTES: usize = 65535;

pub const HEADER_SIZE: usize = 18;

pub const SCTP_PORT: u16 = 5000;

/// `max-message-size` assumed when the remote SDP omits it.
pub const SCTP_MAX_MESSAGE_SIZE: u32 = 65536;

/// `max-message-size` we advertise, matching the vanilla client.
pub const LOCAL_SCTP_MAX_MESSAGE_SIZE: u32 = 262144;

/// Labels of the two data channels NetherNet always opens (guide section 6).
pub const RELIABLE_CHANNEL: &str = "ReliableDataChannel";
pub const UNRELIABLE_CHANNEL: &str = "UnreliableDataChannel";

pub const DEFAULT_PACKET_CHANNEL_CAPACITY: usize = 1024;

/// Offers a server answers before any of them establishes.
pub const DEFAULT_MAX_PENDING: usize = 64;

/// Unestablished offers a server answers from one network id.
pub const DEFAULT_MAX_PENDING_PER_NETWORK_ID: usize = 4;

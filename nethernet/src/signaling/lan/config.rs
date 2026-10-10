//! Settings for the LAN signaler.
use crate::protocol::constants::LAN_DISCOVERY_PORT;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LanSignalerConfig {
    /// UDP port that discovery traffic uses.
    pub discovery_port: u16,

    /// Where discovery requests are broadcast; `None` disables broadcasting.
    pub broadcast_address: Option<SocketAddr>,

    /// Time between discovery requests.
    pub broadcast_interval: Duration,

    /// A peer not heard from for this long is forgotten.
    pub address_timeout: Duration,

    /// Delay between retransmissions of a signal that has had no reply.
    pub signal_retry_interval: Duration,

    /// Retransmissions after the first send; zero disables them.
    pub signal_retries: u32,
}

impl Default for LanSignalerConfig {
    fn default() -> Self {
        Self {
            discovery_port: LAN_DISCOVERY_PORT,
            broadcast_address: None,
            broadcast_interval: Duration::from_secs(2),
            address_timeout: Duration::from_secs(15),
            signal_retry_interval: Duration::from_millis(500),
            signal_retries: 3,
        }
    }
}

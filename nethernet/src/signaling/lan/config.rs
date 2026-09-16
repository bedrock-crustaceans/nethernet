//! Options of LAN discovery.

use crate::protocol::constants::LAN_DISCOVERY_PORT;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LanSignalerConfig {
    /// Port servers listen on for discovery requests. Vanilla clients broadcast to
    /// [`LAN_DISCOVERY_PORT`], so it should only be changed for testing.
    pub discovery_port: u16,

    /// Address discovery requests are broadcast to. Servers, which answer requests rather
    /// than sending them, leave this empty.
    pub broadcast_address: Option<SocketAddr>,

    /// Interval between broadcasts of discovery requests.
    pub broadcast_interval: Duration,

    /// Time an address of a remote network is kept after its last packet.
    pub address_timeout: Duration,

    /// Interval between retransmissions of a signal that has not been answered.
    ///
    /// Discovery runs over UDP, so a lost offer is never noticed by either side and the
    /// connection simply never happens.
    pub signal_retry_interval: Duration,

    /// How often a signal is retransmitted before it is given up on.
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

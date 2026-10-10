use crate::protocol::constants::LAN_DISCOVERY_PORT;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LanSignalerConfig {
    pub discovery_port: u16,

    pub broadcast_address: Option<SocketAddr>,

    pub broadcast_interval: Duration,

    pub address_timeout: Duration,

    pub signal_retry_interval: Duration,

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

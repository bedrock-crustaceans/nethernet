//! Errors of the LAN discovery state machine.

use crate::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LanSignalerError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// A signal names a network that is not a discovery ID.
    #[error("invalid network ID: {0}")]
    InvalidNetworkId(String),

    /// A signal names a network no packet has been received from yet, so there is no
    /// address to send it to.
    #[error("no address known for network {0}")]
    UnknownNetwork(u64),
}

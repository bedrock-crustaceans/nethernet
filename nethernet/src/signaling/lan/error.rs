//! Errors from the LAN signaler.
use crate::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LanSignalerError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("invalid network ID: {0}")]
    InvalidNetworkId(String),

    #[error("no address known for network {0}")]
    UnknownNetwork(u64),
}

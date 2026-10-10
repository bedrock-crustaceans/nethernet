//! Errors from the HTTP signaler.
use crate::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpSignalerError {
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("no join is waiting for connection {0}")]
    UnknownConnection(u64),
}

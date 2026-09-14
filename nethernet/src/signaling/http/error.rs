//! Errors of the HTTP endpoint state machine.

use crate::error::ProtocolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpSignalerError {
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// An answer or a rejection names a join that is not waiting for one.
    #[error("no join is waiting for connection {0}")]
    UnknownConnection(u64),
}

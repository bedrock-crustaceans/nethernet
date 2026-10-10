//! Error types for the transport and signaling layers.
use nethernet::admission::AdmissionError;
use nethernet::error::ProtocolError;
use nethernet::identity::error::IdentityError;
use nethernet::signaling::http::join::StatusResponseError;
use std::io;
use thiserror::Error;

pub use nethernet::error::SignalErrorCode;

#[derive(Debug, Error)]
pub enum NetherError {
    #[error("ICE error: {0}")]
    Ice(String),

    #[error("DTLS error: {0}")]
    Dtls(String),

    #[error("SCTP error: {0}")]
    Sctp(String),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),

    /// The HTTP server has neither an identity nor allow_unsigned_answers (guide section 5.2).
    #[error("HTTP signaling requires a server identity")]
    IdentityRequired,

    #[error("Admission error: {0}")]
    Admission(#[from] AdmissionError),

    #[error("Signaling error: {0}")]
    Signaling(#[from] SignalingError),

    #[error("Status error: {0}")]
    Status(#[from] StatusResponseError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Data channel error: {0}")]
    DataChannel(String),

    #[error("Message parse error: {0}")]
    MessageParse(String),

    #[error("Message too large: exceeds maximum size of {0} bytes")]
    MessageTooLarge(usize),

    #[error("Operation timed out")]
    Timeout,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// The remote refused the connection with a signaling error code.
    #[error("connection failed with code {0:?}")]
    Signaled(SignalErrorCode),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum SignalingError {
    #[error("Failed to send signal: {0}")]
    SendFailed(String),

    #[error("Failed to receive signal: {0}")]
    ReceiveFailed(String),

    #[error("Invalid signal: {0}")]
    InvalidSignal(String),

    #[error("Signaling stopped")]
    Stopped,

    #[error("Network ID not found: {0}")]
    NetworkIdNotFound(u64),

    #[error("Credential error: {0}")]
    CredentialError(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, NetherError>;

use nethernet::error::ProtocolError;
use nethernet::identity::error::IdentityError;
use std::io;
use thiserror::Error;

pub use nethernet::error::SignalErrorCode;

/// Errors related to the NetherNet protocol.
#[derive(Debug, Error)]
pub enum NethernetError {
    /// WebRTC connection error
    #[error("WebRTC error: {0}")]
    WebRtc(#[from] webrtc::error::Error),

    /// ICE connection error
    #[error("ICE error: {0}")]
    Ice(String),

    /// DTLS connection error
    #[error("DTLS error: {0}")]
    Dtls(String),

    /// SCTP connection error
    #[error("SCTP error: {0}")]
    Sctp(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// The identity of a description did not hold up
    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),

    /// Signaling error
    #[error("Signaling error: {0}")]
    Signaling(#[from] SignalingError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Connection already closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Data channel error
    #[error("Data channel error: {0}")]
    DataChannel(String),

    /// Message parse error
    #[error("Message parse error: {0}")]
    MessageParse(String),

    /// Message too large error
    #[error("Message too large: exceeds maximum size of {0} bytes")]
    MessageTooLarge(usize),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Error signaled by the remote connection
    #[error("connection failed with code {0:?}")]
    Signaled(SignalErrorCode),

    /// General error
    #[error("{0}")]
    Other(String),
}

/// Errors related to signaling operations.
#[derive(Debug, Error)]
pub enum SignalingError {
    /// Signal send error
    #[error("Failed to send signal: {0}")]
    SendFailed(String),

    /// Signal receive error
    #[error("Failed to receive signal: {0}")]
    ReceiveFailed(String),

    /// Invalid signal
    #[error("Invalid signal: {0}")]
    InvalidSignal(String),

    /// Signaling stopped
    #[error("Signaling stopped")]
    Stopped,

    /// Network ID not found
    #[error("Network ID not found: {0}")]
    NetworkIdNotFound(u64),

    /// Credential error
    #[error("Credential error: {0}")]
    CredentialError(String),

    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, NethernetError>;

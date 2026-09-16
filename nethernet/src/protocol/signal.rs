use crate::error::{ProtocolError, SignalErrorCode};
use std::fmt;
use std::str::FromStr;

/// The type of a [`Signal`], named on the wire as `CONNECTREQUEST`, `CONNECTRESPONSE`,
/// `CANDIDATEADD` and `CONNECTERROR` respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    Offer,
    Answer,
    Candidate,
    Error,
}

impl SignalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalType::Offer => "CONNECTREQUEST",
            SignalType::Answer => "CONNECTRESPONSE",
            SignalType::Candidate => "CANDIDATEADD",
            SignalType::Error => "CONNECTERROR",
        }
    }
}

impl FromStr for SignalType {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CONNECTREQUEST" => Ok(SignalType::Offer),
            "CONNECTRESPONSE" => Ok(SignalType::Answer),
            "CANDIDATEADD" => Ok(SignalType::Candidate),
            "CONNECTERROR" => Ok(SignalType::Error),
            _ => Err(ProtocolError::Other(format!("Unknown signal type: {}", s))),
        }
    }
}

impl fmt::Display for SignalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// NetherNet signal message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub signal_type: SignalType,
    pub connection_id: u64,
    /// The SDP, ICE candidate, or error code, depending on `signal_type`.
    pub data: String,
    pub network_id: String,
}

impl Signal {
    /// Constructs a Signal from its components.
    pub fn new(
        signal_type: SignalType,
        connection_id: u64,
        data: String,
        network_id: String,
    ) -> Self {
        Self {
            signal_type,
            connection_id,
            data,
            network_id,
        }
    }

    pub fn offer(connection_id: u64, sdp: String, network_id: String) -> Self {
        Self::new(SignalType::Offer, connection_id, sdp, network_id)
    }

    pub fn answer(connection_id: u64, sdp: String, network_id: String) -> Self {
        Self::new(SignalType::Answer, connection_id, sdp, network_id)
    }

    pub fn candidate(connection_id: u64, candidate: String, network_id: String) -> Self {
        Self::new(SignalType::Candidate, connection_id, candidate, network_id)
    }

    pub fn error(connection_id: u64, error_code: SignalErrorCode, network_id: String) -> Self {
        Self::new(
            SignalType::Error,
            connection_id,
            (error_code as u32).to_string(),
            network_id,
        )
    }

    /// Parses a `TYPE CONNECTION_ID DATA` string and assigns the given network ID.
    pub fn from_string(s: &str, network_id: String) -> Result<Self, ProtocolError> {
        let parts: Vec<&str> = s.splitn(3, ' ').collect();
        if parts.len() != 3 {
            return Err(ProtocolError::Other(format!(
                "Invalid signal format: expected 3 parts, got {}",
                parts.len()
            )));
        }

        let signal_type = SignalType::from_str(parts[0])?;
        let connection_id = parts[1]
            .parse::<u64>()
            .map_err(|e| ProtocolError::Other(format!("Failed to parse connection ID: {}", e)))?;
        let data = parts[2].to_string();

        Ok(Self {
            signal_type,
            connection_id,
            data,
            network_id,
        })
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.signal_type.as_str(),
            self.connection_id,
            self.data
        )
    }
}

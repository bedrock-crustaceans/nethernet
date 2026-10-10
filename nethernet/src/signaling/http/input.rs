//! Inputs accepted by the HTTP signaler.
use crate::error::SignalErrorCode;
use crate::protocol::packet::discovery::ServerData;
use http::Request;
use std::net::SocketAddr;
use std::time::Instant;

/// Why a pending join is refused, sent as 403, 504 or 503.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Rejected,

    Timeout,

    Unavailable,
}

impl From<SignalErrorCode> for RejectReason {
    fn from(code: SignalErrorCode) -> Self {
        match code {
            SignalErrorCode::NegotiationTimeout
            | SignalErrorCode::NegotiationTimeoutWaitingForAccept
            | SignalErrorCode::NegotiationTimeoutWaitingForResponse
            | SignalErrorCode::InactivityTimeout => RejectReason::Timeout,
            SignalErrorCode::IncomingConnectionIgnored | SignalErrorCode::NotLoggedIn => {
                RejectReason::Rejected
            }
            _ => RejectReason::Unavailable,
        }
    }
}

#[derive(Debug, Clone)]
pub enum HttpSignalerInput {
    Connected(u64, SocketAddr, Instant),

    Request {
        connection: u64,
        request: Box<Request<String>>,
        now: Instant,
    },

    /// Completes a pending join with the answer SDP.
    Answer {
        connection_id: u64,
        sdp: String,
    },

    Reject {
        connection_id: u64,
        reason: RejectReason,
    },

    SetServerData(Box<ServerData>),

    Closed(u64),

    /// Expires overdue joins and queues a `Wait` for the next deadline.
    Update(Instant),
}

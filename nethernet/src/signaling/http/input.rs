//! Inputs of the HTTP endpoint state machine.

use crate::error::SignalErrorCode;
use crate::protocol::packet::discovery::ServerData;
use http::Request;
use std::net::SocketAddr;
use std::time::Instant;

/// Why an offer did not produce an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The peer was turned away before a connection was started for it.
    Rejected,

    /// Nothing produced an answer in time.
    Timeout,

    /// The host is not in a state to answer.
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
    /// A connection was accepted from the given address.
    Connected(u64, SocketAddr, Instant),

    /// A request arrived on a connection. `proxied` is the source a trusted proxy
    /// declared in its PROXY header, which the caller reads off the connection.
    Request {
        connection: u64,
        request: Box<Request<String>>,
        proxied: Option<SocketAddr>,
        now: Instant,
    },

    /// The answer of the transport for a join that is waiting for one.
    Answer { connection_id: u64, sdp: String },

    /// The transport turned the join away.
    Reject {
        connection_id: u64,
        reason: RejectReason,
    },

    /// The data the status endpoint advertises.
    SetServerData(Box<ServerData>),

    /// A connection was closed, whether by the peer or by the host.
    Closed(u64),

    /// Drives the expiry of the joins that are waiting for an answer.
    Update(Instant),
}

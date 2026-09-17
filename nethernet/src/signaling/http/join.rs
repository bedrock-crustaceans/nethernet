//! What a peer posts to join over the HTTP endpoint, and how it reads the answer back.
//!
//! Transport-agnostic: building and sending the actual request, and reading the response
//! off the wire, is left to the caller.

use crate::error::SignalErrorCode;
use crate::signaling::http::JOIN_PATH;
use thiserror::Error;

/// Content type a join request's body, and a successful answer's body, are sent as.
pub const CONTENT_TYPE: &str = "application/sdp";

/// User agent Minecraft's own HTTP client sends, which some servers require.
pub const CLIENT_USER_AGENT: &str = "libhttpclient/1.0.0.0";

/// Largest answer accepted from a server.
pub const MAX_ANSWER_SIZE: usize = 1 << 20;

/// The path a peer posts its offer to on the given network.
pub fn join_path(network_id: &str) -> String {
    format!("{JOIN_PATH}/{network_id}")
}

/// Why a join response could not be used as an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JoinResponseError {
    #[error("server answered with status {0}")]
    Status(u16),

    #[error("server sent no answer")]
    Empty,

    #[error("answer exceeds {0} bytes")]
    TooLarge(usize),

    /// A join that fails is answered with the numeric error code as the body, per the
    /// HTTP signaling guide, rather than out of band.
    #[error("server rejected the offer with code {0:?}")]
    Rejected(SignalErrorCode),
}

/// Checks a join response's status and body for the answer, per the HTTP signaling
/// guide's section 5.
pub fn validate_join_response(status: u16, body: &str) -> Result<(), JoinResponseError> {
    if !(200..300).contains(&status) {
        return Err(JoinResponseError::Status(status));
    }
    if body.is_empty() {
        return Err(JoinResponseError::Empty);
    }
    if body.len() > MAX_ANSWER_SIZE {
        return Err(JoinResponseError::TooLarge(body.len()));
    }
    if let Ok(code) = body.trim().parse::<u32>() {
        return Err(JoinResponseError::Rejected(code.into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_join_path_names_the_network() {
        assert_eq!(join_path("1234"), "/v1/join/1234");
    }

    #[test]
    fn a_successful_answer_is_accepted() {
        assert_eq!(validate_join_response(200, "v=0\r\n"), Ok(()));
    }

    #[test]
    fn a_failed_status_is_rejected() {
        assert_eq!(
            validate_join_response(500, "v=0\r\n"),
            Err(JoinResponseError::Status(500))
        );
    }

    #[test]
    fn an_empty_answer_is_rejected() {
        assert_eq!(
            validate_join_response(200, ""),
            Err(JoinResponseError::Empty)
        );
    }

    #[test]
    fn an_oversized_answer_is_rejected() {
        let body = "a".repeat(MAX_ANSWER_SIZE + 1);
        assert_eq!(
            validate_join_response(200, &body),
            Err(JoinResponseError::TooLarge(body.len()))
        );
    }

    #[test]
    fn a_bare_error_code_is_a_rejection() {
        assert_eq!(
            validate_join_response(200, "4"),
            Err(JoinResponseError::Rejected(SignalErrorCode::from(4)))
        );
    }
}

use crate::error::{ProtocolError, SignalErrorCode};
use crate::protocol::packet::discovery::ServerData;
use crate::signaling::http::JOIN_PATH;
use thiserror::Error;

pub const CONTENT_TYPE: &str = "application/sdp";

pub const CLIENT_USER_AGENT: &str = "libhttpclient/1.0.0.0";

pub const MAX_ANSWER_SIZE: usize = 1 << 20;

pub const STATUS_PATH: &str = JOIN_PATH;

pub fn join_path(network_id: &str) -> String {
    format!("{JOIN_PATH}/{network_id}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JoinResponseError {
    #[error("server answered with status {0}")]
    Status(u16),

    #[error("server sent no answer")]
    Empty,

    #[error("answer exceeds {0} bytes")]
    TooLarge(usize),

    #[error("server rejected the offer with code {0:?}")]
    Rejected(SignalErrorCode),
}

#[derive(Debug, Error)]
pub enum StatusResponseError {
    #[error("server answered with status {0}")]
    Status(u16),

    #[error("server sent malformed server data: {0}")]
    Malformed(#[source] ProtocolError),
}

pub fn validate_status_response(
    status: u16,
    body: &[u8],
) -> Result<ServerData, StatusResponseError> {
    if !(200..300).contains(&status) {
        return Err(StatusResponseError::Status(status));
    }
    ServerData::from_json(&String::from_utf8_lossy(body)).map_err(StatusResponseError::Malformed)
}

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

    const VANILLA_STATUS: &str = "{\"name\":\"Server\",\"protocol\":0,\"version\":\"\",\"level\":\"World\",\"players\":1,\"maxPlayers\":8,\"gameType\":0}";

    #[test]
    fn the_status_path_is_the_join_path() {
        assert_eq!(STATUS_PATH, "/v1/join");
    }

    #[test]
    fn a_status_body_is_read_as_server_data() {
        let data = validate_status_response(200, VANILLA_STATUS.as_bytes()).unwrap();
        assert_eq!(data, ServerData::from_json(VANILLA_STATUS).unwrap());
        assert_eq!(data.server_name, "Server");
        assert_eq!(data.max_player_count, 8);
    }

    #[test]
    fn a_failed_status_response_is_rejected() {
        assert!(matches!(
            validate_status_response(404, b""),
            Err(StatusResponseError::Status(404))
        ));
    }

    #[test]
    fn garbage_status_body_is_malformed() {
        assert!(matches!(
            validate_status_response(200, b"not json"),
            Err(StatusResponseError::Malformed(_))
        ));
    }

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

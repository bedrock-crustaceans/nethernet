//! ICE server credentials, historically used for gathering relayed candidates.
//!
//! NetherNet never gathers or accepts anything but a single UDP host candidate per side
//! (see the HTTP signaling guide, section 6) - there is no STUN/TURN relay to authenticate
//! against, so nothing in this crate currently consumes these. The types are kept for
//! signaling implementations that decode them off the wire (e.g. as part of a broader
//! session-info payload) and for callers that still carry them across the wire.

use serde::{Deserialize, Serialize};

/// Credentials for the ICE servers a connection may gather candidates from.
///
/// They are typically received from a signaling connection and expire, in which case
/// new credentials must be obtained before negotiating another connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(rename = "ExpirationInSeconds")]
    pub expiration_in_seconds: i32,

    #[serde(rename = "TurnAuthServers")]
    pub ice_servers: Vec<IceServer>,
}

/// A single ICE server with the credentials required to authenticate with it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IceServer {
    #[serde(rename = "Username")]
    pub username: String,

    #[serde(rename = "Password")]
    pub password: String,

    #[serde(rename = "Urls")]
    pub urls: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_decode_from_signaling_json() {
        let json = r#"{"ExpirationInSeconds":86400,"TurnAuthServers":[{"Username":"user","Password":"secret","Urls":["turn:127.0.0.1:3478"]}]}"#;
        let credentials: Credentials = serde_json::from_str(json).unwrap();

        assert_eq!(credentials.expiration_in_seconds, 86400);
        assert_eq!(credentials.ice_servers[0].urls.len(), 1);
    }
}

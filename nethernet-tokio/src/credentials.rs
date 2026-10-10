use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(rename = "ExpirationInSeconds")]
    pub expiration_in_seconds: i32,

    #[serde(rename = "TurnAuthServers")]
    pub ice_servers: Vec<IceServer>,
}

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

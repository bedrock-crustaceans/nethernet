//! The player a validated token describes.
use crate::identity::error::{IdentityError, Result};
use crate::identity::jwt::Claims;
use p384::ecdsa::VerifyingKey;
use p384::pkcs8::EncodePublicKey;
use std::net::SocketAddr;

/// A player whose token passed validation.
#[derive(Debug, Clone)]
pub struct PlayerInfo {
    pub xuid: Option<String>,

    pub display_name: Option<String>,

    /// Network id the offer was signaled from.
    pub network_id: String,

    /// Signaling source address, which can differ from the media address.
    pub remote_address: Option<SocketAddr>,

    pub claims: Claims,
}

impl PlayerInfo {
    pub fn new(claims: Claims, network_id: String, remote_address: Option<SocketAddr>) -> Self {
        Self {
            xuid: claims.xuid().map(str::to_string),
            display_name: claims.display_name().map(str::to_string),
            network_id,
            remote_address,
            claims,
        }
    }

    pub fn client_public_key(&self) -> Result<VerifyingKey> {
        self.claims.client_public_key()
    }

    /// Fails with `KeyMismatch` unless the key equals the token's `cpk`.
    pub fn verify_login_key(&self, identity_public_key: &VerifyingKey) -> Result<()> {
        let expected = self.client_public_key()?;
        let (expected, presented) = (
            expected
                .to_public_key_der()
                .map_err(|e| IdentityError::Key(e.to_string()))?,
            identity_public_key
                .to_public_key_der()
                .map_err(|e| IdentityError::Key(e.to_string()))?,
        );

        match expected.as_bytes() == presented.as_bytes() {
            true => Ok(()),
            false => Err(IdentityError::KeyMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::server::ServerIdentity;
    use crate::identity::trust::{TokenTrust, validate_sdp};
    use std::time::{SystemTime, UNIX_EPOCH};

    const NOW: SystemTime = UNIX_EPOCH;

    fn offer(identity: &str) -> String {
        format!(
            "v=0\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=identity:{}\r\n\
             a=fingerprint:sha-256 AB:CD\r\n",
            identity
        )
    }

    #[test]
    fn a_login_key_that_signed_no_assertion_is_refused() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let other = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server
            .augment(&offer(""))
            .unwrap()
            .replace("a=identity:\r\n", "");

        let claims = validate_sdp(&answer, &TokenTrust::Any, NOW).unwrap();
        let player = PlayerInfo::new(claims, "1234".to_string(), None);

        assert!(player.verify_login_key(server.verifying_key()).is_ok());
        assert!(matches!(
            player.verify_login_key(other.verifying_key()).unwrap_err(),
            IdentityError::KeyMismatch
        ));
    }
}

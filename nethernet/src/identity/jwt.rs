//! Parsing of the compact JWS serialization and of the claims a token carries.

use crate::identity::error::{IdentityError, Result};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Clock skew allowed when an expiry is checked.
const LEEWAY: Duration = Duration::from_secs(60);

/// The header of a signed token.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Header {
    #[serde(default)]
    pub alg: String,

    #[serde(default)]
    pub kid: Option<String>,
}

/// A token split into the parts the signature covers.
#[derive(Debug, Clone)]
pub struct Jws {
    pub header: Header,
    pub signing_input: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Jws {
    /// Splits a compact serialization, decoding its header, payload and signature.
    pub fn parse(compact: &str) -> Result<Self> {
        let mut parts = compact.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(IdentityError::Malformed(
                "expected three parts in the compact serialization".to_string(),
            ));
        };

        Ok(Self {
            header: serde_json::from_slice(&decode(header)?)
                .map_err(|e| IdentityError::Malformed(format!("invalid header: {}", e)))?,
            signing_input: format!("{}.{}", header, payload),
            payload: decode(payload)?,
            signature: decode(signature)?,
        })
    }

    /// Splits a detached serialization, which carries its payload elsewhere, and attaches
    /// the payload the signature is supposed to cover.
    pub fn parse_detached(compact: &str, payload: &str) -> Result<Self> {
        let mut parts = compact.split('.');
        let (Some(header), Some(""), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(IdentityError::Malformed(
                "expected a detached compact serialization".to_string(),
            ));
        };

        let encoded = URL_SAFE_NO_PAD.encode(payload);
        Ok(Self {
            header: serde_json::from_slice(&decode(header)?)
                .map_err(|e| IdentityError::Malformed(format!("invalid header: {}", e)))?,
            signing_input: format!("{}.{}", header, encoded),
            payload: payload.as_bytes().to_vec(),
            signature: decode(signature)?,
        })
    }

    /// Verifies an ES384 signature against the given key.
    pub fn verify_es384(&self, key: &VerifyingKey) -> Result<()> {
        if self.header.alg != "ES384" {
            return Err(IdentityError::Malformed(format!(
                "expected ES384, got {}",
                self.header.alg
            )));
        }

        let signature = Signature::from_slice(&self.signature)
            .map_err(|e| IdentityError::Malformed(format!("invalid signature: {}", e)))?;

        key.verify(self.signing_input.as_bytes(), &signature)
            .map_err(|_| IdentityError::FingerprintMismatch)
    }

    /// Decodes the payload as the claims of a token.
    pub fn claims(&self) -> Result<Claims> {
        serde_json::from_slice(&self.payload)
            .map(Claims::new)
            .map_err(|e| IdentityError::Malformed(format!("invalid claims: {}", e)))
    }
}

/// The claims of a token, kept as they were written so that anything the protocol does
/// not read is still available to the application.
#[derive(Debug, Clone, Default)]
pub struct Claims {
    values: serde_json::Map<String, Value>,
}

impl Claims {
    pub fn new(values: serde_json::Map<String, Value>) -> Self {
        Self { values }
    }

    /// The claims as they were written.
    pub fn values(&self) -> &serde_json::Map<String, Value> {
        &self.values
    }

    /// Returns a claim as a string, for claims this crate does not read itself.
    pub fn string(&self, claim: &str) -> Option<&str> {
        self.values.get(claim).and_then(Value::as_str)
    }

    /// The subject of the token.
    pub fn subject(&self) -> Option<&str> {
        self.string("sub")
    }

    /// The issuer of the token.
    pub fn issuer(&self) -> Option<&str> {
        self.string("iss")
    }

    /// The Xbox user ID of the player, which is only attested when the token is issued by
    /// the Minecraft authorization service.
    pub fn xuid(&self) -> Option<&str> {
        self.string("xid")
    }

    /// The Xbox gamertag of the player, attested under the same terms as the user ID.
    pub fn display_name(&self) -> Option<&str> {
        self.string("xname")
    }

    /// The audiences the token is addressed to.
    pub fn audience(&self) -> Vec<&str> {
        match self.values.get("aud") {
            Some(Value::String(audience)) => vec![audience.as_str()],
            Some(Value::Array(audiences)) => audiences.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        }
    }

    /// The expiry of the token.
    pub fn expiry(&self) -> Option<SystemTime> {
        let seconds = self.values.get("exp").and_then(Value::as_u64)?;
        Some(UNIX_EPOCH + Duration::from_secs(seconds))
    }

    /// The key the peer proved it holds, from the `cpk` claim.
    ///
    /// Nothing below the transport ties this to whatever identity the application carries
    /// afterwards. If the login step presents its own signed identity, compare its key to
    /// this one and reject a mismatch, or a peer can present an identity it captured
    /// elsewhere and did not sign for.
    pub fn client_public_key(&self) -> Result<VerifyingKey> {
        let cpk = self.string("cpk").ok_or_else(|| {
            IdentityError::ClientPublicKey("the token carries no cpk".to_string())
        })?;

        let der = STANDARD
            .decode(cpk)
            .map_err(|e| IdentityError::ClientPublicKey(format!("invalid base64: {}", e)))?;

        VerifyingKey::from_public_key_der(&der)
            .map_err(|e| IdentityError::ClientPublicKey(format!("not a key on P-384: {}", e)))
    }

    /// Checks that the token carries an expiry and is within it.
    pub fn check_expiry(&self, now: SystemTime) -> Result<()> {
        let expiry = self
            .expiry()
            .ok_or_else(|| IdentityError::Untrusted("the token carries no expiry".to_string()))?;

        match now <= expiry + LEEWAY {
            true => Ok(()),
            false => Err(IdentityError::Untrusted(
                "the token has expired".to_string(),
            )),
        }
    }
}

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| IdentityError::Malformed(format!("invalid base64url: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(value: Value) -> Claims {
        Claims::new(value.as_object().unwrap().clone())
    }

    #[test]
    fn an_audience_is_read_in_both_shapes() {
        assert_eq!(claims(json!({"aud": "one"})).audience(), vec!["one"]);
        assert_eq!(
            claims(json!({"aud": ["one", "two"]})).audience(),
            vec!["one", "two"]
        );
        assert!(claims(json!({})).audience().is_empty());
    }

    #[test]
    fn a_token_without_an_expiry_is_refused() {
        assert!(claims(json!({})).check_expiry(UNIX_EPOCH).is_err());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let claims = claims(json!({"exp": 1000}));

        assert!(
            claims
                .check_expiry(UNIX_EPOCH + Duration::from_secs(900))
                .is_ok()
        );
        assert!(
            claims
                .check_expiry(UNIX_EPOCH + Duration::from_secs(2000))
                .is_err()
        );
    }

    #[test]
    fn a_malformed_serialization_is_refused() {
        assert!(Jws::parse("one.two").is_err());
        assert!(Jws::parse_detached("one.two.three", "{}").is_err());
    }
}

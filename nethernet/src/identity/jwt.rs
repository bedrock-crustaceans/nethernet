//! Compact JWS parsing and token claims.
use crate::identity::error::{IdentityError, Result};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LEEWAY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Header {
    #[serde(default)]
    pub alg: String,

    #[serde(default)]
    pub kid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Jws {
    pub header: Header,
    pub signing_input: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Jws {
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

    /// Parses a `header..signature` JWS, taking the payload from the second argument.
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

    pub fn claims(&self) -> Result<Claims> {
        serde_json::from_slice(&self.payload)
            .map(Claims::new)
            .map_err(|e| IdentityError::Malformed(format!("invalid claims: {}", e)))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Claims {
    values: serde_json::Map<String, Value>,
}

impl Claims {
    pub fn new(values: serde_json::Map<String, Value>) -> Self {
        Self { values }
    }

    pub fn values(&self) -> &serde_json::Map<String, Value> {
        &self.values
    }

    pub fn string(&self, claim: &str) -> Option<&str> {
        self.values.get(claim).and_then(Value::as_str)
    }

    pub fn subject(&self) -> Option<&str> {
        self.string("sub")
    }

    pub fn issuer(&self) -> Option<&str> {
        self.string("iss")
    }

    pub fn xuid(&self) -> Option<&str> {
        self.string("xid")
    }

    pub fn display_name(&self) -> Option<&str> {
        self.string("xname")
    }

    pub fn audience(&self) -> Vec<&str> {
        match self.values.get("aud") {
            Some(Value::String(audience)) => vec![audience.as_str()],
            Some(Value::Array(audiences)) => audiences.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        }
    }

    pub fn expiry(&self) -> Option<SystemTime> {
        let seconds = self.values.get("exp").and_then(Value::as_u64)?;
        Some(UNIX_EPOCH + Duration::from_secs(seconds))
    }

    /// The `cpk` claim, a base64 DER P-384 public key.
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

    /// Refuses a token with no `exp`, or expired by more than 60 seconds.
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

    #[test]
    fn a_token_is_accepted_up_to_sixty_seconds_past_its_expiry() {
        let claims = claims(json!({"exp": 1000}));

        assert!(
            claims
                .check_expiry(UNIX_EPOCH + Duration::from_secs(1060))
                .is_ok()
        );
    }

    #[test]
    fn a_token_is_refused_sixty_one_seconds_past_its_expiry() {
        let claims = claims(json!({"exp": 1000}));

        let error = claims
            .check_expiry(UNIX_EPOCH + Duration::from_secs(1061))
            .unwrap_err();

        assert!(matches!(error, IdentityError::Untrusted(_)));
    }

    #[test]
    fn a_token_without_an_expiry_is_untrusted() {
        let error = claims(json!({})).check_expiry(UNIX_EPOCH).unwrap_err();

        assert!(matches!(error, IdentityError::Untrusted(_)));
    }

    #[test]
    fn a_claim_set_without_a_cpk_has_no_client_public_key() {
        let error = claims(json!({"exp": 1000}))
            .client_public_key()
            .unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_p256_cpk_is_not_a_client_public_key() {
        let p256 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtn+9sKRdn6eczaU797AJwdk2VIjMDgYtLt9T+j92M4M0iFDyYPp5OkOVORuYpZSO1HNH94EzVi5bmaHqKbZdUw==";

        let error = claims(json!({"cpk": p256}))
            .client_public_key()
            .unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_cpk_that_is_not_base64_is_not_a_client_public_key() {
        let error = claims(json!({"cpk": "***"}))
            .client_public_key()
            .unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_detached_serialization_with_a_payload_is_malformed() {
        let error = Jws::parse_detached("e30.e30.AA", "{}").unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_detached_serialization_takes_its_payload_from_the_argument() {
        let jws = Jws::parse_detached("eyJhbGciOiJFUzM4NCJ9..AA", "{}").unwrap();

        assert_eq!(jws.header.alg, "ES384");
        assert_eq!(jws.signing_input, "eyJhbGciOiJFUzM4NCJ9.e30");
        assert_eq!(jws.payload, b"{}");
    }
}

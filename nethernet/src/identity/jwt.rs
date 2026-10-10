//! Token claims.
use crate::identity::error::{IdentityError, Result};
use crate::identity::jwk::EcJwk;
pub use crate::identity::jws::{Header, Jws};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p384::ecdsa::VerifyingKey;
use p384::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LEEWAY: Duration = Duration::from_secs(60);

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

    /// The `cpk` claim: a P-384 key as a JWK object or as a base64 SPKI DER string.
    pub fn client_public_key(&self) -> Result<VerifyingKey> {
        match self.values.get("cpk") {
            None => Err(IdentityError::ClientPublicKey(
                "the token carries no cpk".to_string(),
            )),
            Some(Value::String(cpk)) => Self::spki_key(cpk),
            Some(object @ Value::Object(_)) => {
                let jwk = EcJwk::deserialize(object)
                    .map_err(|e| IdentityError::ClientPublicKey(format!("invalid JWK: {}", e)))?;
                VerifyingKey::try_from(&jwk)
            }
            Some(_) => Err(IdentityError::ClientPublicKey(
                "the cpk is neither a string nor a JWK object".to_string(),
            )),
        }
    }

    fn spki_key(cpk: &str) -> Result<VerifyingKey> {
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

    const FIXTURE_SPKI: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV+juifBq9vg+w/V/BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ/F3rYoRoHM1";

    fn fixture_jwk() -> Value {
        json!({
            "kty": "EC",
            "crv": "P-384",
            "x": "QKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV-j",
            "y": "uifBq9vg-w_V_BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ_F3rYoRoHM1",
        })
    }

    #[test]
    fn a_jwk_cpk_is_the_same_key_as_the_spki_string_cpk() {
        let from_jwk = claims(json!({"cpk": fixture_jwk()}))
            .client_public_key()
            .unwrap();
        let from_spki = claims(json!({"cpk": FIXTURE_SPKI}))
            .client_public_key()
            .unwrap();

        assert_eq!(from_jwk, from_spki);
    }

    #[test]
    fn a_jwk_cpk_on_another_curve_or_type_is_not_a_client_public_key() {
        for (field, value) in [("crv", "P-256"), ("kty", "RSA")] {
            let mut jwk = fixture_jwk();
            jwk[field] = json!(value);

            let error = claims(json!({"cpk": jwk})).client_public_key().unwrap_err();

            assert!(matches!(error, IdentityError::ClientPublicKey(_)));
        }
    }

    #[test]
    fn a_jwk_cpk_with_malformed_coordinates_is_not_a_client_public_key() {
        let x = fixture_jwk()["x"].as_str().unwrap().to_string();
        let malformed = [
            x[..x.len() - 4].to_string(),
            format!("{}AAAA", x),
            "***".to_string(),
            x.replace('-', "+"),
            format!("{}=", &x[..x.len() - 1]),
        ];

        for x in malformed {
            let mut jwk = fixture_jwk();
            jwk["x"] = json!(x);

            let error = claims(json!({"cpk": jwk})).client_public_key().unwrap_err();

            assert!(matches!(error, IdentityError::ClientPublicKey(_)));
        }
    }

    #[test]
    fn a_jwk_cpk_missing_a_coordinate_is_not_a_client_public_key() {
        let error = claims(json!({"cpk": {"kty": "EC", "crv": "P-384"}}))
            .client_public_key()
            .unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_cpk_that_is_an_array_or_a_number_is_not_a_client_public_key() {
        for cpk in [json!([fixture_jwk()]), json!(384)] {
            let error = claims(json!({"cpk": cpk})).client_public_key().unwrap_err();

            assert!(matches!(error, IdentityError::ClientPublicKey(_)));
        }
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

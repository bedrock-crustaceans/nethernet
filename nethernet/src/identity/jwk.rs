//! JSON Web Keys: RSA keys that verify RS256 tokens and the P-384 key carried in `cpk`.
use crate::identity::error::{IdentityError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p384::ecdsa::VerifyingKey as EcVerifyingKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{BoxedUint, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kty: String,

    #[serde(default)]
    pub kid: Option<String>,

    #[serde(default)]
    pub n: Option<String>,

    #[serde(default)]
    pub e: Option<String>,
}

impl JwkSet {
    /// Keys matching `kid`, or every key when the token names none.
    pub fn candidates(&self, kid: Option<&str>) -> Vec<&Jwk> {
        match kid {
            Some(kid) => self
                .keys
                .iter()
                .filter(|key| key.kid.as_deref() == Some(kid))
                .collect(),
            None => self.keys.iter().collect(),
        }
    }

    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|key| key.kid.as_deref() == Some(kid))
    }
}

impl Jwk {
    pub fn verify_rs256(&self, signing_input: &[u8], signature: &[u8]) -> Result<()> {
        if self.kty != "RSA" {
            return Err(IdentityError::Untrusted(format!(
                "unsupported key type {}",
                self.kty
            )));
        }

        let (Some(n), Some(e)) = (self.n.as_deref(), self.e.as_deref()) else {
            return Err(IdentityError::Untrusted("incomplete RSA key".to_string()));
        };

        let modulus = BoxedUint::from_be_slice_vartime(&decode(n)?);
        let exponent = BoxedUint::from_be_slice_vartime(&decode(e)?);
        let key = RsaPublicKey::new(modulus, exponent)
            .map_err(|e| IdentityError::Untrusted(format!("invalid RSA key: {}", e)))?;
        let signature = Signature::try_from(signature)
            .map_err(|_| IdentityError::Untrusted("signature mismatch".to_string()))?;

        VerifyingKey::<Sha256>::new(key)
            .verify(signing_input, &signature)
            .map_err(|_| IdentityError::Untrusted("signature mismatch".to_string()))
    }
}

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| IdentityError::Untrusted(format!("invalid base64url in key: {}", e)))
}

const P384_COORDINATE_LEN: usize = 48;

/// A P-384 public key as a JSON Web Key (RFC 7517, RFC 7518 section 6.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl EcJwk {
    fn coordinate(name: &str, value: &str) -> Result<[u8; P384_COORDINATE_LEN]> {
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|e| {
            IdentityError::ClientPublicKey(format!("{} is not unpadded base64url: {}", name, e))
        })?;

        bytes.try_into().map_err(|bytes: Vec<u8>| {
            IdentityError::ClientPublicKey(format!(
                "{} is {} bytes, expected {}",
                name,
                bytes.len(),
                P384_COORDINATE_LEN
            ))
        })
    }
}

impl TryFrom<&EcJwk> for EcVerifyingKey {
    type Error = IdentityError;

    fn try_from(jwk: &EcJwk) -> Result<Self> {
        if jwk.kty != "EC" {
            return Err(IdentityError::ClientPublicKey(format!(
                "unsupported key type {}",
                jwk.kty
            )));
        }
        if jwk.crv != "P-384" {
            return Err(IdentityError::ClientPublicKey(format!(
                "unsupported curve {}",
                jwk.crv
            )));
        }

        let x = EcJwk::coordinate("x", &jwk.x)?;
        let y = EcJwk::coordinate("y", &jwk.y)?;
        let mut point = Vec::with_capacity(1 + 2 * P384_COORDINATE_LEN);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);

        EcVerifyingKey::from_sec1_bytes(&point)
            .map_err(|e| IdentityError::ClientPublicKey(format!("not a key on P-384: {}", e)))
    }
}

impl From<&EcVerifyingKey> for EcJwk {
    fn from(key: &EcVerifyingKey) -> Self {
        let point = key.to_sec1_point(false);
        let coordinate = |bytes: Option<&[u8]>| URL_SAFE_NO_PAD.encode(bytes.unwrap_or_default());

        Self {
            kty: "EC".to_string(),
            crv: "P-384".to_string(),
            x: coordinate(point.x().map(|x| x.as_slice())),
            y: coordinate(point.y().map(|y| y.as_slice())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &str = "QKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV-j";
    const Y: &str = "uifBq9vg-w_V_BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ_F3rYoRoHM1";
    const SPKI: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV+juifBq9vg+w/V/BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ/F3rYoRoHM1";

    fn jwk(x: &str, y: &str) -> EcJwk {
        EcJwk {
            kty: "EC".to_string(),
            crv: "P-384".to_string(),
            x: x.to_string(),
            y: y.to_string(),
        }
    }

    fn fixture_key() -> EcVerifyingKey {
        use base64::engine::general_purpose::STANDARD;
        use p384::pkcs8::DecodePublicKey;
        EcVerifyingKey::from_public_key_der(&STANDARD.decode(SPKI).unwrap()).unwrap()
    }

    #[test]
    fn a_jwk_with_the_fixture_coordinates_is_the_fixture_key() {
        let key = EcVerifyingKey::try_from(&jwk(X, Y)).unwrap();

        assert_eq!(key, fixture_key());
    }

    #[test]
    fn the_fixture_key_becomes_the_jwk_with_the_fixture_coordinates() {
        assert_eq!(EcJwk::from(&fixture_key()), jwk(X, Y));
    }

    #[test]
    fn a_jwk_with_another_curve_is_refused() {
        let mut other = jwk(X, Y);
        other.crv = "P-256".to_string();

        let error = EcVerifyingKey::try_from(&other).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_jwk_with_another_key_type_is_refused() {
        let mut other = jwk(X, Y);
        other.kty = "RSA".to_string();

        let error = EcVerifyingKey::try_from(&other).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn coordinates_of_the_wrong_length_are_refused() {
        let short = &X[..X.len() - 4];
        let long = format!("{}AAAA", X);

        for (x, y) in [
            (short, Y),
            (X, short),
            (long.as_str(), Y),
            (X, long.as_str()),
        ] {
            let error = EcVerifyingKey::try_from(&jwk(x, y)).unwrap_err();

            assert!(matches!(error, IdentityError::ClientPublicKey(_)));
        }
    }

    #[test]
    fn coordinates_that_are_not_unpadded_base64url_are_refused() {
        let standard = X.replace('-', "+").replace('_', "/");
        let padded = format!("{}==", &X[..X.len() - 2]);

        for x in ["***", standard.as_str(), padded.as_str()] {
            let error = EcVerifyingKey::try_from(&jwk(x, Y)).unwrap_err();

            assert!(matches!(error, IdentityError::ClientPublicKey(_)));
        }
    }

    #[test]
    fn coordinates_off_the_curve_are_refused() {
        let error = EcVerifyingKey::try_from(&jwk(Y, X)).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }
}

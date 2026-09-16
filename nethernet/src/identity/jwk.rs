//! The key set an issuer publishes, and verification of the tokens it signs.
//!
//! Fetching the set is left to the caller, which keeps this crate free of IO. A set is
//! usually read from the `.well-known/keys` endpoint of the issuer and refreshed when a
//! token names a key that is not in it yet.

use crate::identity::error::{IdentityError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{BigUint, RsaPublicKey};
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// A set of keys an issuer signs its tokens with.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// A single key of a [`JwkSet`]. Only RSA keys are read, as that is what the Minecraft
/// authorization service publishes.
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
    /// Returns the key the token names, or every key of the set when it names none.
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

    /// Reports whether the set holds a key with the given ID.
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|key| key.kid.as_deref() == Some(kid))
    }
}

impl Jwk {
    /// Verifies an RS256 signature over the signing input of a token.
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

        let modulus = BigUint::from_bytes_be(&decode(n)?);
        let exponent = BigUint::from_bytes_be(&decode(e)?);
        let key = RsaPublicKey::new(modulus, exponent)
            .map_err(|e| IdentityError::Untrusted(format!("invalid RSA key: {}", e)))?;

        key.verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(signing_input),
            signature,
        )
        .map_err(|_| IdentityError::Untrusted("signature mismatch".to_string()))
    }
}

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| IdentityError::Untrusted(format!("invalid base64url in key: {}", e)))
}

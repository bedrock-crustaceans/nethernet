//! Compact JWS parsing, ES384 signing and verification.
use crate::identity::error::{IdentityError, Result};
use crate::identity::jwt::Claims;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;

const ES384_HEADER: &str = "{\"alg\":\"ES384\"}";

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

    /// Signs `payload` as a compact ES384 JWS.
    pub fn sign(key: &SigningKey, payload: &str) -> Result<String> {
        let (header, payload, signature) = Self::sign_parts(key, payload)?;
        Ok(format!("{}.{}.{}", header, payload, signature))
    }

    /// Signs `payload` as a `header..signature` ES384 JWS with the payload left out.
    pub fn sign_detached(key: &SigningKey, payload: &str) -> Result<String> {
        let (header, _, signature) = Self::sign_parts(key, payload)?;
        Ok(format!("{}..{}", header, signature))
    }

    fn sign_parts(key: &SigningKey, payload: &str) -> Result<(String, String, String)> {
        let header = URL_SAFE_NO_PAD.encode(ES384_HEADER);
        let payload = URL_SAFE_NO_PAD.encode(payload);

        let signature: Signature = key
            .try_sign(format!("{}.{}", header, payload).as_bytes())
            .map_err(|e| IdentityError::Signing(e.to_string()))?;

        Ok((
            header,
            payload,
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        ))
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

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| IdentityError::Malformed(format!("invalid base64url: {}", e)))
}

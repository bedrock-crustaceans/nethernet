//! The server's own identity: a P-384 key and a self-signed token that sign answers.
use crate::identity::error::{IdentityError, Result};
use crate::identity::{Assertion, Identity, Idp, canonical_fingerprint_json};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p384::SecretKey;
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::elliptic_curve::Generate;
use p384::pkcs8::{EncodePublicKey, LineEnding};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Token validity used when no lifetime is given.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Server key and token; keep the key stable across restarts so clients can trust it (guide section 5.2).
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    signing: SigningKey,
    verifying: VerifyingKey,
    domain: String,
    token: String,
}

impl ServerIdentity {
    pub fn generate(domain: impl Into<String>, now: SystemTime) -> Result<Self> {
        Self::generate_with_expiry(domain, now, Some(DEFAULT_TOKEN_LIFETIME))
    }

    /// A `None` lifetime omits `exp`, and validators in this crate refuse tokens without one.
    pub fn generate_with_expiry(
        domain: impl Into<String>,
        now: SystemTime,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
        Self::from_key(SigningKey::generate(), domain, now, lifetime)
    }

    pub fn from_pem(pem: &str, domain: impl Into<String>, now: SystemTime) -> Result<Self> {
        Self::from_pem_with_expiry(pem, domain, now, Some(DEFAULT_TOKEN_LIFETIME))
    }

    pub fn from_pem_with_expiry(
        pem: &str,
        domain: impl Into<String>,
        now: SystemTime,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
        let secret = SecretKey::from_pem(pem)
            .map_err(|e| IdentityError::Key(format!("the PEM holds no key on P-384: {}", e)))?;

        Self::from_key(secret.into(), domain, now, lifetime)
    }

    pub fn from_key(
        signing: SigningKey,
        domain: impl Into<String>,
        now: SystemTime,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
        let verifying = *signing.verifying_key();
        let domain = domain.into();

        let der = verifying
            .to_public_key_der()
            .map_err(|e| IdentityError::Key(e.to_string()))?;

        let mut claims = json!({
            "cpk": STANDARD.encode(der.as_bytes()),
            "iat": seconds(now),
        });
        if !domain.is_empty() {
            claims["iss"] = json!(domain);
        }
        if let Some(lifetime) = lifetime {
            claims["exp"] = json!(seconds(now + lifetime));
        }

        let token = sign(&signing, &claims.to_string())?;

        Ok(Self {
            signing,
            verifying,
            domain,
            token,
        })
    }

    pub fn to_pem(&self) -> Result<String> {
        let secret = SecretKey::from(self.signing.as_nonzero_scalar());
        Ok(secret
            .to_sec1_pem(LineEnding::LF)
            .map_err(|e| IdentityError::Key(e.to_string()))?
            .to_string())
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The base64 identity value signing the fingerprints of `answer`.
    pub fn identity_value(&self, answer: &str) -> Result<String> {
        let fingerprints = canonical_fingerprint_json(answer)?;
        let signed = sign(&self.signing, &fingerprints)?;

        let mut parts = signed.split('.');
        let (Some(header), Some(_), Some(signature)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(IdentityError::Signing(
                "the signature is not a compact serialization".to_string(),
            ));
        };

        Identity {
            idp: Idp {
                domain: self.domain.clone(),
                protocol: "default".to_string(),
            },
            assertion: Assertion {
                token: self.token.clone(),
                fingerprints: format!("{}..{}", header, signature),
            },
        }
        .to_base64()
    }

    /// Inserts a signed `a=identity` line above the first media section of an answer.
    pub fn augment(&self, answer: &str) -> Result<String> {
        let attribute = format!("a=identity:{}", self.identity_value(answer)?);
        let eol = match answer.contains("\r\n") {
            true => "\r\n",
            false => "\n",
        };

        let mut out = String::with_capacity(answer.len() + attribute.len() + eol.len());
        let mut inserted = false;

        for line in answer.split_inclusive(['\n']) {
            if !inserted && line.starts_with("m=") {
                out.push_str(&attribute);
                out.push_str(eol);
                inserted = true;
            }
            out.push_str(line);
        }

        if !inserted {
            out.push_str(&attribute);
            out.push_str(eol);
        }

        Ok(out)
    }
}

fn sign(key: &SigningKey, payload: &str) -> Result<String> {
    let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES384\"}");
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{}.{}", header, payload);

    let signature: Signature = key
        .try_sign(signing_input.as_bytes())
        .map_err(|e| IdentityError::Signing(e.to_string()))?;

    Ok(format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = "v=0\r\n\
        o=- 1 2 IN IP4 127.0.0.1\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=fingerprint:sha-256 AB:CD\r\n";

    #[test]
    fn the_identity_is_inserted_above_the_media_description() {
        let identity = ServerIdentity::generate("example.com", UNIX_EPOCH).unwrap();
        let answer = identity.augment(ANSWER).unwrap();

        let lines: Vec<&str> = answer.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.starts_with("a=identity:"))
            .unwrap();

        assert!(lines[index + 1].starts_with("m="));
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn the_assertion_is_detached() {
        let identity = ServerIdentity::generate("example.com", UNIX_EPOCH).unwrap();
        let value = identity.identity_value(ANSWER).unwrap();
        let parsed = Identity::from_base64(&value).unwrap();

        assert_eq!(parsed.assertion.fingerprints.split("..").count(), 2);
        assert_eq!(parsed.idp.protocol, "default");
    }

    #[test]
    fn a_key_survives_a_pem_round_trip() {
        let identity = ServerIdentity::generate("example.com", UNIX_EPOCH).unwrap();
        let loaded =
            ServerIdentity::from_pem(&identity.to_pem().unwrap(), "example.com", UNIX_EPOCH)
                .unwrap();

        assert_eq!(loaded.verifying_key(), identity.verifying_key());
    }
}

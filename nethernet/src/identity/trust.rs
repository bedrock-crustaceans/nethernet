//! Authentication of the token in a received assertion.
use crate::identity::envelope::{EMPTY_FINGERPRINTS, Identity, canonical_fingerprint_json};
use crate::identity::error::{IdentityError, Result};
use crate::identity::jwk::JwkSet;
use crate::identity::jwt::{Claims, Jws};
use crate::identity::{MINECRAFT_AUDIENCE, MINECRAFT_ISSUER};
use std::time::SystemTime;

/// How the token in a received assertion is authenticated.
#[derive(Debug, Clone)]
pub enum TokenTrust {
    /// RS256 token signed by a key in the set, with the Minecraft issuer and audience.
    Minecraft(JwkSet),

    /// Any well-formed unexpired token; signature, issuer and audience are not checked.
    Any,
}

impl TokenTrust {
    /// Parses the token and checks its expiry, plus signature, issuer and audience under `Minecraft`.
    pub fn claims(&self, identity: &Identity, now: SystemTime) -> Result<Claims> {
        let jws = Jws::parse(&identity.assertion.token)?;
        let claims = jws.claims()?;
        claims.check_expiry(now)?;

        let TokenTrust::Minecraft(keys) = self else {
            return Ok(claims);
        };

        if jws.header.alg != "RS256" {
            return Err(IdentityError::Untrusted(format!(
                "expected RS256, got {}",
                jws.header.alg
            )));
        }

        let candidates = keys.candidates(jws.header.kid.as_deref());
        if candidates.is_empty() {
            return Err(IdentityError::Untrusted(
                "the token names a key that is not published".to_string(),
            ));
        }
        if !candidates.iter().any(|key| {
            key.verify_rs256(jws.signing_input.as_bytes(), &jws.signature)
                .is_ok()
        }) {
            return Err(IdentityError::Untrusted(
                "the token is not signed by the issuer".to_string(),
            ));
        }

        if claims.subject().is_none() {
            return Err(IdentityError::Untrusted(
                "the token carries no subject".to_string(),
            ));
        }
        if claims.issuer() != Some(MINECRAFT_ISSUER) {
            return Err(IdentityError::Untrusted(
                "the token was issued by someone else".to_string(),
            ));
        }
        if !claims.audience().contains(&MINECRAFT_AUDIENCE) {
            return Err(IdentityError::Untrusted(
                "the token is addressed to another audience".to_string(),
            ));
        }

        Ok(claims)
    }
}

/// Checks the token, then that the key in its `cpk` claim signed the SDP fingerprints.
pub fn validate_sdp(sdp: &str, trust: &TokenTrust, now: SystemTime) -> Result<Claims> {
    let identity = Identity::from_sdp(sdp)?;
    let claims = trust.claims(&identity, now)?;

    let fingerprints = canonical_fingerprint_json(sdp)?;
    if fingerprints == EMPTY_FINGERPRINTS {
        return Err(IdentityError::NoFingerprints);
    }

    let jws = Jws::parse_detached(&identity.assertion.fingerprints, &fingerprints)?;
    jws.verify_es384(&claims.client_public_key()?)?;

    Ok(claims)
}

#[cfg(test)]
#[path = "token_trust_tests.rs"]
mod token_trust_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::server::ServerIdentity;
    use std::time::{Duration, UNIX_EPOCH};

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
    fn a_description_without_an_identity_is_refused() {
        let error = validate_sdp("v=0\r\n", &TokenTrust::Any, NOW).unwrap_err();

        assert!(matches!(error, IdentityError::Missing));
    }

    #[test]
    fn an_answer_validates_against_the_identity_it_carries() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment(&offer("")).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        let claims = validate_sdp(&answer, &TokenTrust::Any, NOW).unwrap();

        assert_eq!(claims.issuer(), Some("example.com"));
    }

    #[test]
    fn an_assertion_over_other_fingerprints_is_refused() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment(&offer("")).unwrap();
        let answer = answer
            .replace("a=identity:\r\n", "")
            .replace("AB:CD", "EF:01");

        let error = validate_sdp(&answer, &TokenTrust::Any, NOW).unwrap_err();

        assert!(matches!(error, IdentityError::FingerprintMismatch));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let server =
            ServerIdentity::generate_with_expiry("example.com", NOW, Some(Duration::from_secs(10)))
                .unwrap();
        let answer = server.augment(&offer("")).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        let error =
            validate_sdp(&answer, &TokenTrust::Any, NOW + Duration::from_secs(600)).unwrap_err();

        assert!(matches!(error, IdentityError::Untrusted(_)));
    }
}

//! Identity assertions carried in the SDP `a=identity` attribute (guide section 5).
pub mod error;
pub mod jwk;
pub mod jwt;
pub mod server;

#[cfg(test)]
mod token_trust_tests;

use crate::identity::error::{IdentityError, Result};
use crate::identity::jwk::JwkSet;
use crate::identity::jwt::{Claims, Jws};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p384::ecdsa::VerifyingKey;
use p384::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;

pub use server::ServerIdentity;

/// Endpoint publishing the JWKS that signs Minecraft multiplayer tokens.
pub const MINECRAFT_KEYS_URL: &str =
    "https://authorization.franchise.minecraft-services.net/.well-known/keys";

/// Required `iss` of a token under `TokenTrust::Minecraft`.
pub const MINECRAFT_ISSUER: &str = "https://authorization.franchise.minecraft-services.net/";

/// Required `aud` entry of a token under `TokenTrust::Minecraft`.
pub const MINECRAFT_AUDIENCE: &str = "api://auth-minecraft-services/multiplayer";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Idp {
    #[serde(default)]
    pub domain: String,

    #[serde(default)]
    pub protocol: String,
}

/// A token plus a detached ES384 signature over the SDP fingerprints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Assertion {
    #[serde(default)]
    pub token: String,

    /// Compact JWS with an empty payload, written `header..signature`.
    #[serde(default)]
    pub fingerprints: String,
}

/// A decoded `a=identity` value: base64 JSON whose `assertion` field is itself JSON text.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub idp: Idp,
    pub assertion: Assertion,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Raw {
    #[serde(default)]
    idp: Idp,

    #[serde(default)]
    assertion: String,
}

impl Identity {
    pub fn from_json(json: &str) -> Result<Self> {
        let raw: Raw = serde_json::from_str(json)
            .map_err(|e| IdentityError::Malformed(format!("invalid identity: {}", e)))?;
        let assertion = serde_json::from_str(&raw.assertion)
            .map_err(|e| IdentityError::Malformed(format!("invalid assertion: {}", e)))?;

        Ok(Self {
            idp: raw.idp,
            assertion,
        })
    }

    pub fn from_base64(value: &str) -> Result<Self> {
        let json = STANDARD
            .decode(value.trim())
            .map_err(|e| IdentityError::Malformed(format!("invalid base64: {}", e)))?;
        let json = String::from_utf8(json)
            .map_err(|e| IdentityError::Malformed(format!("invalid UTF-8: {}", e)))?;

        Self::from_json(&json)
    }

    /// Reads the first `a=identity` line, failing with `Missing` when there is none.
    pub fn from_sdp(sdp: &str) -> Result<Self> {
        let value = sdp
            .split(['\r', '\n'])
            .find_map(|line| line.strip_prefix("a=identity:"))
            .ok_or(IdentityError::Missing)?;

        Self::from_base64(value)
    }

    pub fn to_json(&self) -> Result<String> {
        let raw = Raw {
            idp: self.idp.clone(),
            assertion: serde_json::to_string(&self.assertion)
                .map_err(|e| IdentityError::Malformed(e.to_string()))?,
        };

        serde_json::to_string(&raw).map_err(|e| IdentityError::Malformed(e.to_string()))
    }

    pub fn to_base64(&self) -> Result<String> {
        Ok(STANDARD.encode(self.to_json()?))
    }
}

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

/// The exact JSON the fingerprint signature covers; no fingerprint lines give an empty array.
pub fn canonical_fingerprint_json(sdp: &str) -> Result<String> {
    let mut out = String::from("{\"fingerprint\":[");

    for (index, line) in sdp
        .split(['\r', '\n'])
        .filter_map(|line| line.strip_prefix("a=fingerprint:"))
        .enumerate()
    {
        let Some((algorithm, digest)) = line.trim().split_once(' ') else {
            return Err(IdentityError::Malformed(format!(
                "invalid fingerprint line: {}",
                line
            )));
        };

        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"algorithm\":\"{}\",\"digest\":\"{}\"}}",
            algorithm, digest
        ));
    }

    out.push_str("]}");
    Ok(out)
}

const EMPTY_FINGERPRINTS: &str = "{\"fingerprint\":[]}";

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
    fn fingerprints_are_canonicalized_as_the_assertion_covers_them() {
        let sdp = "a=fingerprint:sha-256 AB:CD\r\na=fingerprint:sha-1 EF\r\n";

        assert_eq!(
            canonical_fingerprint_json(sdp).unwrap(),
            "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"AB:CD\"},\
             {\"algorithm\":\"sha-1\",\"digest\":\"EF\"}]}"
        );
    }

    #[test]
    fn a_description_without_fingerprints_canonicalizes_to_an_empty_array() {
        assert_eq!(
            canonical_fingerprint_json("v=0\r\n").unwrap(),
            EMPTY_FINGERPRINTS
        );
    }

    #[test]
    fn an_identity_survives_a_round_trip() {
        let identity = Identity {
            idp: Idp {
                domain: "example.com".to_string(),
                protocol: "default".to_string(),
            },
            assertion: Assertion {
                token: "token".to_string(),
                fingerprints: "header..signature".to_string(),
            },
        };

        let parsed = Identity::from_base64(&identity.to_base64().unwrap()).unwrap();

        assert_eq!(parsed.idp.domain, "example.com");
        assert_eq!(parsed.assertion.token, "token");
        assert_eq!(parsed.assertion.fingerprints, "header..signature");
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

    const GUIDE_DIGEST: &str = "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB";

    const GUIDE_FINGERPRINT_JSON: &str = "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\"}]}";

    const VANILLA_ENVELOPE: &str = "eyJpZHAiOnsiZG9tYWluIjoiYXV0aD4+Pj8uZXhhbXBsZSIsInByb3RvY29sIjoiZGVmYXVsdCJ9LCJhc3NlcnRpb24iOiJ7XCJ0b2tlblwiOlwiYWEuYmIuY2NcIixcImZpbmdlcnByaW50c1wiOlwiaGguLnNzXCJ9In0=";

    const VANILLA_ENVELOPE_URL_SAFE: &str = "eyJpZHAiOnsiZG9tYWluIjoiYXV0aD4-Pj8uZXhhbXBsZSIsInByb3RvY29sIjoiZGVmYXVsdCJ9LCJhc3NlcnRpb24iOiJ7XCJ0b2tlblwiOlwiYWEuYmIuY2NcIixcImZpbmdlcnByaW50c1wiOlwiaGguLnNzXCJ9In0=";

    const VANILLA_ENVELOPE_UNPADDED: &str = "eyJpZHAiOnsiZG9tYWluIjoiYXV0aD4+Pj8uZXhhbXBsZSIsInByb3RvY29sIjoiZGVmYXVsdCJ9LCJhc3NlcnRpb24iOiJ7XCJ0b2tlblwiOlwiYWEuYmIuY2NcIixcImZpbmdlcnByaW50c1wiOlwiaGguLnNzXCJ9In0";

    #[test]
    fn the_guide_fingerprint_canonicalizes_to_the_documented_json() {
        let sdp = format!("a=fingerprint:sha-256 {}\r\n", GUIDE_DIGEST);

        assert_eq!(
            canonical_fingerprint_json(&sdp).unwrap(),
            GUIDE_FINGERPRINT_JSON
        );
    }

    #[test]
    fn lf_only_line_endings_canonicalize_like_crlf() {
        let crlf = "a=fingerprint:sha-256 AB:CD\r\na=fingerprint:sha-1 EF\r\n";
        let lf = "a=fingerprint:sha-256 AB:CD\na=fingerprint:sha-1 EF\n";

        assert_eq!(
            canonical_fingerprint_json(lf).unwrap(),
            canonical_fingerprint_json(crlf).unwrap()
        );
    }

    #[test]
    fn trailing_whitespace_on_a_fingerprint_line_is_trimmed() {
        let sdp = "a=fingerprint:sha-256 AB:CD \t \r\n";

        assert_eq!(
            canonical_fingerprint_json(sdp).unwrap(),
            "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"AB:CD\"}]}"
        );
    }

    #[test]
    fn extra_spaces_between_algorithm_and_digest_stay_in_the_digest() {
        let sdp = "a=fingerprint:sha-256   AB:CD\r\n";

        assert_eq!(
            canonical_fingerprint_json(sdp).unwrap(),
            "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"  AB:CD\"}]}"
        );
    }

    #[test]
    fn fingerprint_lines_are_read_only_at_the_start_of_a_line() {
        let sdp = "m=application\r\na=fingerprint:sha-256 AB:CD\r\nb=a=fingerprint:sha-1 EF\r\n";

        assert_eq!(
            canonical_fingerprint_json(sdp).unwrap(),
            "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"AB:CD\"}]}"
        );
    }

    #[test]
    fn a_fingerprint_line_without_a_space_is_malformed() {
        let error = canonical_fingerprint_json("a=fingerprint:sha-256\r\n").unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn an_empty_fingerprint_line_is_malformed() {
        let error = canonical_fingerprint_json("a=fingerprint:\r\n").unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn an_encoded_identity_starts_with_the_idp_domain_prefix() {
        let identity = Identity {
            idp: Idp {
                domain: "example.com".to_string(),
                protocol: "default".to_string(),
            },
            assertion: Assertion::default(),
        };

        assert!(
            identity
                .to_base64()
                .unwrap()
                .starts_with("eyJpZHAiOnsiZG9tYWluIjoi")
        );
    }

    #[test]
    fn a_vanilla_envelope_decodes_to_its_idp_and_assertion() {
        let identity = Identity::from_base64(VANILLA_ENVELOPE).unwrap();

        assert_eq!(identity.idp.domain, "auth>>>?.example");
        assert_eq!(identity.idp.protocol, "default");
        assert_eq!(identity.assertion.token, "aa.bb.cc");
        assert_eq!(identity.assertion.fingerprints, "hh..ss");
    }

    #[test]
    fn a_vanilla_envelope_re_encodes_to_the_same_value() {
        let identity = Identity::from_base64(VANILLA_ENVELOPE).unwrap();

        assert_eq!(identity.to_base64().unwrap(), VANILLA_ENVELOPE);
    }

    #[test]
    fn an_envelope_is_read_through_surrounding_whitespace() {
        let padded = format!("  {}\r\n", VANILLA_ENVELOPE);

        assert!(Identity::from_base64(&padded).is_ok());
    }

    #[test]
    fn a_url_safe_envelope_is_refused() {
        let error = Identity::from_base64(VANILLA_ENVELOPE_URL_SAFE).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn an_unpadded_envelope_is_refused() {
        let error = Identity::from_base64(VANILLA_ENVELOPE_UNPADDED).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn an_envelope_whose_assertion_is_not_json_is_malformed() {
        let envelope = STANDARD.encode("{\"idp\":{},\"assertion\":\"not json\"}");

        let error = Identity::from_base64(&envelope).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn an_identity_is_read_from_the_first_identity_line_of_an_lf_only_description() {
        let sdp = format!(
            "v=0\na=identity:{}\na=identity:garbage\nm=application 9\n",
            VANILLA_ENVELOPE
        );

        let identity = Identity::from_sdp(&sdp).unwrap();

        assert_eq!(identity.assertion.token, "aa.bb.cc");
    }
}

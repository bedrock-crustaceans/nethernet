//! The identity assertion carried by the descriptions exchanged during signaling.
//!
//! A peer embeds an `a=identity` attribute in its description holding a token and a
//! detached signature over the DTLS fingerprints of that same description. Validating the
//! two together is what ties an identity to the certificate the peer presents, and it is
//! the only thing standing between a connection and an offer replayed by someone else.

pub mod error;
pub mod jwk;
pub mod jwt;
pub mod server;

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

/// Where the keys of the Minecraft authorization service are published.
pub const MINECRAFT_KEYS_URL: &str =
    "https://authorization.franchise.minecraft-services.net/.well-known/keys";

/// The issuer a retail client presents a token from.
pub const MINECRAFT_ISSUER: &str = "https://authorization.franchise.minecraft-services.net/";

/// The audience a token for multiplayer is addressed to.
pub const MINECRAFT_AUDIENCE: &str = "api://auth-minecraft-services/multiplayer";

/// The identity provider that issued an assertion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Idp {
    #[serde(default)]
    pub domain: String,

    #[serde(default)]
    pub protocol: String,
}

/// The token of an identity and the detached signature over the fingerprints it is bound
/// to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Assertion {
    #[serde(default)]
    pub token: String,

    #[serde(default)]
    pub fingerprints: String,
}

/// The identity embedded in a description.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub idp: Idp,
    pub assertion: Assertion,
}

/// The assertion is nested as a JSON string rather than as an object, which is what the
/// clients produce and expect.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Raw {
    #[serde(default)]
    idp: Idp,

    #[serde(default)]
    assertion: String,
}

impl Identity {
    /// Parses an identity from its JSON form.
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

    /// Parses an identity from the base64 form carried by a description.
    pub fn from_base64(value: &str) -> Result<Self> {
        let json = STANDARD
            .decode(value.trim())
            .map_err(|e| IdentityError::Malformed(format!("invalid base64: {}", e)))?;
        let json = String::from_utf8(json)
            .map_err(|e| IdentityError::Malformed(format!("invalid UTF-8: {}", e)))?;

        Self::from_json(&json)
    }

    /// Reads the identity out of a description.
    pub fn from_sdp(sdp: &str) -> Result<Self> {
        let value = sdp
            .split(['\r', '\n'])
            .find_map(|line| line.strip_prefix("a=identity:"))
            .ok_or(IdentityError::Missing)?;

        Self::from_base64(value)
    }

    /// Encodes the identity as JSON.
    pub fn to_json(&self) -> Result<String> {
        let raw = Raw {
            idp: self.idp.clone(),
            assertion: serde_json::to_string(&self.assertion)
                .map_err(|e| IdentityError::Malformed(e.to_string()))?,
        };

        serde_json::to_string(&raw).map_err(|e| IdentityError::Malformed(e.to_string()))
    }

    /// Encodes the identity in the base64 form carried by a description.
    pub fn to_base64(&self) -> Result<String> {
        Ok(STANDARD.encode(self.to_json()?))
    }
}

/// Decides whether the token in an identity is trusted.
///
/// This is only the first half of validating a description. Whichever policy is chosen,
/// the detached signature over the fingerprints is still verified against the `cpk` of the
/// token, which is what ties the identity to the certificate the peer presents.
#[derive(Debug, Clone)]
pub enum TokenTrust {
    /// Verifies the token against the keys of the Minecraft authorization service, which
    /// is what a retail client presents. The keys are fetched by the caller, as this crate
    /// performs no IO of its own.
    Minecraft(JwkSet),

    /// Reads the claims without checking who signed the token, for peers that cannot
    /// present a Minecraft issued one, such as another proxy in the same fleet.
    ///
    /// The `cpk` binding still applies, so the peer must hold the key its token names, and
    /// the token must carry an expiry and be within it. Neither bounds what the token
    /// *says*: the peer signs its own, so the user ID, the gamertag and the expiry itself
    /// are whatever it chose. Nothing here establishes *who* the peer is, so pair it with
    /// an identity check of your own.
    Any,
}

impl TokenTrust {
    /// Returns the claims of the token, provided it is trusted.
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

/// Validates the identity embedded in a description against the fingerprints of that same
/// description.
///
/// The token is trusted as `trust` decides, while the binding between the identity and the
/// certificate is checked either way.
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

/// The canonical JSON the detached signature of an assertion covers.
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

/// The validated identity of a player attempting to join.
///
/// How much of this can be trusted depends on the [`TokenTrust`] the description was
/// validated with. Under [`TokenTrust::Minecraft`] the token is issued by Xbox, so the
/// claims are attested. Under [`TokenTrust::Any`] the peer signed its own token and every
/// claim below is self asserted, with only [`PlayerInfo::client_public_key`] bound to a key
/// the peer had to hold.
#[derive(Debug, Clone)]
pub struct PlayerInfo {
    /// The Xbox user ID of the player.
    pub xuid: Option<String>,

    /// The Xbox gamertag of the player.
    pub display_name: Option<String>,

    /// The network ID the player is joining with.
    pub network_id: String,

    /// The address the offer was signaled from, if the signaling can tell.
    pub remote_address: Option<SocketAddr>,

    /// The full set of validated claims, for anything not surfaced above.
    pub claims: Claims,
}

impl PlayerInfo {
    /// Builds the player info from the claims of a validated description.
    pub fn new(claims: Claims, network_id: String, remote_address: Option<SocketAddr>) -> Self {
        Self {
            xuid: claims.xuid().map(str::to_string),
            display_name: claims.display_name().map(str::to_string),
            network_id,
            remote_address,
            claims,
        }
    }

    /// The key the peer proved it holds.
    pub fn client_public_key(&self) -> Result<VerifyingKey> {
        self.claims.client_public_key()
    }

    /// Checks that a login chain is signed with the key the transport was opened with.
    ///
    /// On RakNet the encryption handshake does this on its own: the session key comes out
    /// of a key exchange against the identity key of the chain, so only its holder can read
    /// what follows. NetherNet runs over DTLS and skips that handshake, which leaves the
    /// chain unbound, and a chain is replayable until something binds it. The assertion
    /// binds it here, because the peer proved it holds the key the assertion names before
    /// the transport was accepted, and that is the same key the chain is signed with.
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
        assert_eq!(canonical_fingerprint_json("v=0\r\n").unwrap(), EMPTY_FINGERPRINTS);
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
        let answer = server.augment_answer(&offer("")).unwrap();
        let answer = answer.replace("a=identity:\r\n", "");

        let claims = validate_sdp(&answer, &TokenTrust::Any, NOW).unwrap();

        assert_eq!(claims.issuer(), Some("example.com"));
    }

    #[test]
    fn an_assertion_over_other_fingerprints_is_refused() {
        let server = ServerIdentity::generate("example.com", NOW).unwrap();
        let answer = server.augment_answer(&offer("")).unwrap();
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
        let answer = server.augment_answer(&offer("")).unwrap();
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
            .augment_answer(&offer(""))
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

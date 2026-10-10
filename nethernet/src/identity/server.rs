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
    use crate::identity::jwt::Jws;
    use crate::identity::{TokenTrust, validate_sdp};
    use serde_json::json;

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

    const SEC1_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDk5SqsJQCnsweXt71qJWhPrKAhe9tX/HOPqM6kjTi5M8qMeSx8mdPr
uVWNoqH3h9qgBwYFK4EEACKhZANiAARAqrmHdAfGA4B7HM7srmt5yYcAURGiB/Hu
KfCBZMo0q3Jy/Z6wxSnyWeOd8WU5X6O6J8Gr2+D7D9X8Fh+xaDyPt2Z7rVGnwVih
Oy/Uu1zzizzcYTJMluYn8XetihGgczU=
-----END EC PRIVATE KEY-----
";

    const PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDk5SqsJQCnsweXt71q
JWhPrKAhe9tX/HOPqM6kjTi5M8qMeSx8mdPruVWNoqH3h9qhZANiAARAqrmHdAfG
A4B7HM7srmt5yYcAURGiB/HuKfCBZMo0q3Jy/Z6wxSnyWeOd8WU5X6O6J8Gr2+D7
D9X8Fh+xaDyPt2Z7rVGnwVihOy/Uu1zzizzcYTJMluYn8XetihGgczU=
-----END PRIVATE KEY-----
";

    const FIXTURE_CPK: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQKq5h3QHxgOAexzO7K5recmHAFERogfx7inwgWTKNKtycv2esMUp8lnjnfFlOV+juifBq9vg+w/V/BYfsWg8j7dme61Rp8FYoTsv1Ltc84s83GEyTJbmJ/F3rYoRoHM1";

    const FIXTURE_NOW_SECONDS: u64 = 1_700_000_000;

    const FIXTURE_ANSWER: &str = "v=0\r\n\
        o=- 1 2 IN IP4 127.0.0.1\r\n\
        s=-\r\n\
        a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=sctp-port:5000\r\n";

    const GOLDEN_IDENTITY_VALUE: &str = "eyJpZHAiOnsiZG9tYWluIjoiZXhhbXBsZS5jb20iLCJwcm90b2NvbCI6ImRlZmF1bHQifSwiYXNzZXJ0aW9uIjoie1widG9rZW5cIjpcImV5SmhiR2NpT2lKRlV6TTROQ0o5LmV5SmpjR3NpT2lKTlNGbDNSVUZaU0V0dldrbDZhakJEUVZGWlJrczBSVVZCUTBsRVdXZEJSVkZMY1RWb00xRkllR2RQUVdWNGVrODNTelZ5WldOdFNFRkdSVkp2WjJaNE4ybHVkMmRYVkV0T1MzUjVZM1l5WlhOTlZYQTRiRzVxYm1aR2JFOVdLMnAxYVdaQ2NUbDJaeXQzTDFZdlFsbG1jMWRuT0dvM1pHMWxOakZTY0RoR1dXOVVjM1l4VEhSak9EUnpPRE5IUlhsVVNtSnRTaTlHTTNKWmIxSnZTRTB4SWl3aVpYaHdJam94TnpBd01EZzJOREF3TENKcFlYUWlPakUzTURBd01EQXdNREFzSW1semN5STZJbVY0WVcxd2JHVXVZMjl0SW4wLjRIenhFOEtqeHU5RHI1VGVVclo5OUlta0lYdnAzVmJiVzJjajZUQ0RROVVweDVPWlRlSjdHVjZOYWk5UFNUZ05qM1VEMTVCNVgzc294R1hqS3Y3U0xmbEtKdXFFdUdtMlhhXzBwakEwRzZIRzlDUkN2b01zN081V2c3eWlZNFFWXCIsXCJmaW5nZXJwcmludHNcIjpcImV5SmhiR2NpT2lKRlV6TTROQ0o5Li4td2JVV1U4d2t5RTA1bnBtS2RyX0VLN0ZkZWR3X3dnaWdtQkJRM0pGQndISklRMFVZR19aMk9VdHc4UUdrUTJyWDJFZzFKUXYzeS1Zbks5VzJHME9nTVVZdDRCUF84VnB1bHE0TzltdnV3ZFJVcEo2RjRNLXFLWGpTaUVXQWtMY1wifSJ9";

    fn fixture_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW_SECONDS)
    }

    fn fixture_identity() -> ServerIdentity {
        ServerIdentity::from_pem(SEC1_PEM, "example.com", fixture_now()).unwrap()
    }

    fn fixture_cpk_key() -> VerifyingKey {
        use p384::pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_der(&STANDARD.decode(FIXTURE_CPK).unwrap()).unwrap()
    }

    fn token_with_claims(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES384\"}");
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{}.{}.AA", header, payload)
    }

    fn answer_asserting(token: &str, fingerprints: &str) -> String {
        let identity = Identity {
            idp: Idp {
                domain: "example.com".to_string(),
                protocol: "default".to_string(),
            },
            assertion: Assertion {
                token: token.to_string(),
                fingerprints: fingerprints.to_string(),
            },
        };
        format!(
            "v=0\r\na=fingerprint:sha-256 AB:CD\r\na=identity:{}\r\nm=application 9\r\n",
            identity.to_base64().unwrap()
        )
    }

    #[test]
    fn a_sec1_pem_loads_with_a_fixed_public_key() {
        let identity = fixture_identity();

        assert_eq!(identity.verifying_key(), &fixture_cpk_key());
        assert_eq!(identity.domain(), "example.com");
    }

    #[test]
    fn the_token_cpk_is_the_fixed_base64_public_key_der() {
        let jws = Jws::parse(fixture_identity().token()).unwrap();
        let claims = jws.claims().unwrap();

        assert_eq!(claims.string("cpk"), Some(FIXTURE_CPK));
        assert_eq!(claims.issuer(), Some("example.com"));
        assert_eq!(
            claims.expiry(),
            Some(fixture_now() + DEFAULT_TOKEN_LIFETIME)
        );
        assert_eq!(jws.header.alg, "ES384");
    }

    #[test]
    fn a_sec1_pem_is_written_back_unchanged() {
        assert_eq!(fixture_identity().to_pem().unwrap(), SEC1_PEM);
    }

    #[test]
    fn a_pkcs8_pem_loads_with_the_same_public_key() {
        let identity = ServerIdentity::from_pem(PKCS8_PEM, "example.com", fixture_now()).unwrap();

        assert_eq!(identity.verifying_key(), &fixture_cpk_key());
    }

    #[test]
    fn a_pem_that_is_not_a_key_is_a_key_error() {
        let error =
            ServerIdentity::from_pem("not a pem", "example.com", fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Key(_)));
    }

    #[test]
    fn the_fixed_key_signs_a_fixed_answer_deterministically() {
        let first = fixture_identity().identity_value(FIXTURE_ANSWER).unwrap();
        let second = fixture_identity().identity_value(FIXTURE_ANSWER).unwrap();

        assert_eq!(first, second);
        assert_eq!(first, GOLDEN_IDENTITY_VALUE);
    }

    #[test]
    fn the_fixed_answer_is_augmented_above_its_media_section() {
        let augmented = fixture_identity().augment(FIXTURE_ANSWER).unwrap();
        let attribute = format!("a=identity:{}\r\n", GOLDEN_IDENTITY_VALUE);
        let (head, tail) = FIXTURE_ANSWER.split_once("m=").unwrap();

        assert_eq!(augmented, format!("{}{}m={}", head, attribute, tail));
    }

    #[test]
    fn the_augmented_fixed_answer_validates_under_any_trust() {
        let augmented = fixture_identity().augment(FIXTURE_ANSWER).unwrap();

        let claims = validate_sdp(&augmented, &TokenTrust::Any, fixture_now()).unwrap();

        assert_eq!(claims.client_public_key().unwrap(), fixture_cpk_key());
    }

    #[test]
    fn an_lf_only_answer_is_augmented_with_lf_endings() {
        let answer = FIXTURE_ANSWER.replace("\r\n", "\n");
        let augmented = fixture_identity().augment(&answer).unwrap();

        assert!(!augmented.contains('\r'));
        let lines: Vec<&str> = augmented.lines().collect();
        let index = lines
            .iter()
            .position(|line| line.starts_with("a=identity:"))
            .unwrap();
        assert!(lines[index + 1].starts_with("m="));
        assert_eq!(
            augmented.replace(&format!("a=identity:{}\n", GOLDEN_IDENTITY_VALUE), ""),
            answer
        );
    }

    #[test]
    fn an_answer_without_a_media_section_gets_the_identity_appended() {
        let answer = "v=0\r\na=fingerprint:sha-256 AB:CD\r\n";
        let augmented = fixture_identity().augment(answer).unwrap();

        assert!(augmented.starts_with(answer));
        let appended = &augmented[answer.len()..];
        assert!(appended.starts_with("a=identity:"));
        assert!(appended.ends_with("\r\n"));
        assert_eq!(appended.matches('\n').count(), 1);
    }

    #[test]
    fn an_answer_without_a_trailing_newline_gets_its_identity_glued_on() {
        let answer = "a=fingerprint:sha-256 AB:CD";
        let augmented = fixture_identity().augment(answer).unwrap();

        assert!(augmented.starts_with("a=fingerprint:sha-256 AB:CDa=identity:"));
    }

    #[test]
    fn a_description_without_fingerprint_lines_is_refused_as_having_none() {
        let token = fixture_identity().token().to_string();
        let sdp =
            answer_asserting(&token, "e30..AA").replace("a=fingerprint:sha-256 AB:CD\r\n", "");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::NoFingerprints));
    }

    #[test]
    fn a_fingerprint_line_without_a_space_is_refused_by_validation() {
        let token = fixture_identity().token().to_string();
        let sdp = answer_asserting(&token, "e30..AA").replace("sha-256 AB:CD", "sha-256");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_fingerprint_signature_with_another_algorithm_is_malformed() {
        let token = fixture_identity().token().to_string();
        let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES256\"}");
        let sdp = answer_asserting(&token, &format!("{}..AA", header));

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_fingerprint_signature_with_a_payload_segment_is_malformed() {
        let token = fixture_identity().token().to_string();
        let header = URL_SAFE_NO_PAD.encode("{\"alg\":\"ES384\"}");
        let sdp = answer_asserting(&token, &format!("{}.e30.AA", header));

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::Malformed(_)));
    }

    #[test]
    fn a_token_without_a_cpk_is_refused_with_a_client_public_key_error() {
        let token = token_with_claims(json!({"exp": FIXTURE_NOW_SECONDS + 60}));
        let sdp = answer_asserting(&token, "e30..AA");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_token_with_a_p256_cpk_is_refused_with_a_client_public_key_error() {
        let p256 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtn+9sKRdn6eczaU797AJwdk2VIjMDgYtLt9T+j92M4M0iFDyYPp5OkOVORuYpZSO1HNH94EzVi5bmaHqKbZdUw==";
        let token = token_with_claims(json!({"exp": FIXTURE_NOW_SECONDS + 60, "cpk": p256}));
        let sdp = answer_asserting(&token, "e30..AA");

        let error = validate_sdp(&sdp, &TokenTrust::Any, fixture_now()).unwrap_err();

        assert!(matches!(error, IdentityError::ClientPublicKey(_)));
    }

    #[test]
    fn a_token_is_accepted_sixty_seconds_past_its_expiry_and_refused_after() {
        let identity = ServerIdentity::from_pem_with_expiry(
            SEC1_PEM,
            "example.com",
            fixture_now(),
            Some(Duration::from_secs(100)),
        )
        .unwrap();
        let answer = identity.augment(FIXTURE_ANSWER).unwrap();
        let expiry = fixture_now() + Duration::from_secs(100);

        assert!(validate_sdp(&answer, &TokenTrust::Any, expiry + Duration::from_secs(60)).is_ok());
        let error =
            validate_sdp(&answer, &TokenTrust::Any, expiry + Duration::from_secs(61)).unwrap_err();
        assert!(matches!(error, IdentityError::Untrusted(_)));
    }
}

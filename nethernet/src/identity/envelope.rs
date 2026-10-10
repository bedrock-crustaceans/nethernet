//! The identity envelope and the canonical JSON that a fingerprint signature covers.
use crate::identity::error::{IdentityError, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::json;

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

/// The `(algorithm, digest)` pairs of the `a=fingerprint` lines of `sdp`, in order.
pub fn sdp_fingerprints(sdp: &str) -> Result<Vec<(String, String)>> {
    let mut fingerprints = Vec::new();

    for line in sdp
        .split(['\r', '\n'])
        .filter_map(|line| line.strip_prefix("a=fingerprint:"))
    {
        let Some((algorithm, digest)) = line.trim().split_once(' ') else {
            return Err(IdentityError::Malformed(format!(
                "invalid fingerprint line: {}",
                line
            )));
        };

        fingerprints.push((algorithm.to_string(), digest.to_string()));
    }

    Ok(fingerprints)
}

/// The signed payload for a list of `(algorithm, digest)` pairs, with keys in sorted order.
pub fn fingerprint_payload(fingerprints: &[(String, String)]) -> String {
    let entries: Vec<_> = fingerprints
        .iter()
        .map(|(algorithm, digest)| json!({"algorithm": algorithm, "digest": digest}))
        .collect();

    json!({"fingerprint": entries}).to_string()
}

/// The exact JSON the fingerprint signature covers; no fingerprint lines give an empty array.
pub fn canonical_fingerprint_json(sdp: &str) -> Result<String> {
    Ok(fingerprint_payload(&sdp_fingerprints(sdp)?))
}

pub(crate) const EMPTY_FINGERPRINTS: &str = "{\"fingerprint\":[]}";

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(algorithm: &str, digest: &str) -> (String, String) {
        (algorithm.to_string(), digest.to_string())
    }

    #[test]
    fn fingerprints_are_written_in_order_with_sorted_keys() {
        let payload = fingerprint_payload(&[pair("sha-256", "AB:CD"), pair("sha-1", "EF")]);

        assert_eq!(
            payload,
            "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"AB:CD\"},\
             {\"algorithm\":\"sha-1\",\"digest\":\"EF\"}]}"
        );
    }

    #[test]
    fn no_fingerprints_give_an_empty_array() {
        assert_eq!(fingerprint_payload(&[]), "{\"fingerprint\":[]}");
    }

    #[test]
    fn a_digest_with_quotes_is_escaped() {
        let payload = fingerprint_payload(&[pair("sha-256", "A\"B")]);

        assert!(payload.contains("A\\\"B"));
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

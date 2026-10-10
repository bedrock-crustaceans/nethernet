use crate::error::ProtocolError;
use rtc::crypto::RTCCryptoProvider;
use rtc::dtls::crypto::Certificate;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) fn crypto_provider() -> Result<Arc<dyn RTCCryptoProvider>, ProtocolError> {
    rtc::crypto::default_provider()
        .map_err(|e| ProtocolError::Other(format!("crypto provider: {e}")))
}

pub fn generate() -> Result<Certificate, ProtocolError> {
    Certificate::generate_self_signed(vec!["nethernet".to_string()], crypto_provider()?.crypto())
        .map_err(|e| ProtocolError::Other(format!("generate certificate: {e}")))
}

pub fn fingerprint(certificate: &Certificate) -> Result<(String, String), ProtocolError> {
    let der = certificate
        .certificate
        .first()
        .ok_or_else(|| ProtocolError::Other("certificate has no DER bytes".to_string()))?;

    let digest = Sha256::digest(der.as_ref());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    Ok(("sha-256".to_string(), hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex() {
        let cert = generate().unwrap();
        let (algorithm, digest) = fingerprint(&cert).unwrap();

        assert_eq!(algorithm, "sha-256");
        assert_eq!(digest.len(), 32 * 2 + 31);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
        assert_eq!(digest, digest.to_uppercase());
    }

    #[test]
    fn each_certificate_has_a_distinct_fingerprint() {
        let (_, a) = fingerprint(&generate().unwrap()).unwrap();
        let (_, b) = fingerprint(&generate().unwrap()).unwrap();
        assert_ne!(a, b);
    }
}

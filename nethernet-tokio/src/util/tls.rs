//! The TLS a host serves its HTTP endpoint over.

use crate::error::{NethernetError, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

/// Builds the TLS configuration from a certificate chain and a private key, both PEM.
///
/// The chain is served as it is written, so the leaf certificate has to come first and any
/// intermediates after it.
pub async fn from_pem(
    certificate_chain: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
) -> Result<Arc<ServerConfig>> {
    let chain = tokio::fs::read(certificate_chain.as_ref()).await?;
    let key = tokio::fs::read(private_key.as_ref()).await?;

    from_pem_bytes(&chain, &key)
}

/// Builds the TLS configuration from a certificate chain and a private key already read.
pub fn from_pem_bytes(certificate_chain: &[u8], private_key: &[u8]) -> Result<Arc<ServerConfig>> {
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(certificate_chain))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| NethernetError::Other(format!("read certificate chain: {}", e)))?;

    if chain.is_empty() {
        return Err(NethernetError::Other(
            "the certificate chain holds no certificate".to_string(),
        ));
    }

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::Cursor::new(private_key))
            .map_err(|e| NethernetError::Other(format!("read private key: {}", e)))?
            .ok_or_else(|| NethernetError::Other("the PEM holds no private key".to_string()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| NethernetError::Other(format!("build the TLS configuration: {}", e)))?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pem_without_a_certificate_is_refused() {
        let error = from_pem_bytes(b"", b"").unwrap_err();

        assert!(error.to_string().contains("no certificate"), "{error}");
    }
}

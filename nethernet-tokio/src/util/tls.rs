//! rustls server configuration from PEM files.
use crate::error::{NetherError, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::{Arc, Once};

static PROVIDER: Once = Once::new();

/// Installs ring as the process-wide rustls provider unless one already is; reqwest needs one.
pub(crate) fn ensure_crypto_provider() {
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn from_pem(
    certificate_chain: impl AsRef<Path>,
    private_key: impl AsRef<Path>,
) -> Result<Arc<ServerConfig>> {
    let chain = tokio::fs::read(certificate_chain.as_ref()).await?;
    let key = tokio::fs::read(private_key.as_ref()).await?;

    from_pem_bytes(&chain, &key)
}

/// Fails when the chain has no certificate or the PEM holds no private key.
pub fn from_pem_bytes(certificate_chain: &[u8], private_key: &[u8]) -> Result<Arc<ServerConfig>> {
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(certificate_chain))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| NetherError::Other(format!("read certificate chain: {}", e)))?;

    if chain.is_empty() {
        return Err(NetherError::Other(
            "the certificate chain holds no certificate".to_string(),
        ));
    }

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::Cursor::new(private_key))
            .map_err(|e| NetherError::Other(format!("read private key: {}", e)))?
            .ok_or_else(|| NetherError::Other("the PEM holds no private key".to_string()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| NetherError::Other(format!("build the TLS configuration: {}", e)))?;

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

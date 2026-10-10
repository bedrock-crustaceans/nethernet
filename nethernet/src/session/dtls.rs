use crate::error::ProtocolError;
use crate::protocol::webrtc::certificate::crypto_provider;
use bytes::BytesMut;
use rtc::dtls::config::{ClientAuthType, ConfigBuilder};
use rtc::dtls::crypto::Certificate;
use rtc::dtls::endpoint::Endpoint;
pub use rtc::dtls::endpoint::EndpointEvent;
use rtc::dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rtc::shared::{TransportProtocol, error::Error as SharedError};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedRole {
    Client,
    Server,
}

impl ResolvedRole {
    pub fn from_remote_announced(remote: crate::protocol::webrtc::DtlsRole) -> Self {
        use crate::protocol::webrtc::DtlsRole;
        match remote {
            DtlsRole::Client => Self::Server,
            DtlsRole::Server | DtlsRole::Auto => Self::Client,
        }
    }
}

pub struct DtlsLayer {
    endpoint: Endpoint,
    remote_addr: SocketAddr,
}

impl DtlsLayer {
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        role: ResolvedRole,
        certificate: Certificate,
        remote_fingerprint: (String, String),
        now: Instant,
    ) -> Result<DtlsLayer, ProtocolError> {
        let is_client = role == ResolvedRole::Client;

        let config = ConfigBuilder::default()
            .with_crypto_provider(crypto_provider()?)
            .with_certificates(vec![certificate])
            .with_insecure_skip_verify(true)
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_verify_peer_certificate(Some(verify_fingerprint(remote_fingerprint)))
            .with_srtp_protection_profiles(vec![
                SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
                SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ])
            .build(is_client, Some(remote_addr))
            .map_err(|e| ProtocolError::Other(format!("build DTLS config: {e}")))?;
        let config = Arc::new(config);

        let mut endpoint = Endpoint::new(
            local_addr,
            TransportProtocol::UDP,
            (!is_client).then(|| config.clone()),
        );

        if is_client {
            endpoint
                .connect(now, remote_addr, config, None)
                .map_err(|e| ProtocolError::Other(format!("start DTLS handshake: {e}")))?;
        }

        Ok(Self {
            endpoint,
            remote_addr,
        })
    }

    pub fn handle_read(
        &mut self,
        data: &[u8],
        now: Instant,
    ) -> Result<Vec<EndpointEvent>, ProtocolError> {
        self.endpoint
            .read(now, self.remote_addr, None, BytesMut::from(data))
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    pub fn write(&mut self, data: &[u8], now: Instant) -> Result<(), ProtocolError> {
        self.endpoint
            .write(now, self.remote_addr, data)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    pub fn poll_transmit(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.endpoint
            .poll_transmit()
            .map(|msg| (msg.message.to_vec(), msg.transport.peer_addr))
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), ProtocolError> {
        let _ = self.endpoint.handle_timeout(self.remote_addr, now);
        Ok(())
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.endpoint.poll_timeout(&self.remote_addr)
    }
}

fn verify_fingerprint(expected: (String, String)) -> rtc::dtls::config::VerifyPeerCertificateFn {
    Arc::new(move |presented_certs, _verified_chains| {
        let Some(cert) = presented_certs.first() else {
            return Err(SharedError::ErrFingerprintMismatch);
        };

        let digest = Sha256::digest(cert.as_slice());
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");

        if expected.0.eq_ignore_ascii_case("sha-256") && hex.eq_ignore_ascii_case(&expected.1) {
            Ok(())
        } else {
            Err(SharedError::ErrFingerprintMismatch)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::webrtc::certificate;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    #[test]
    fn client_and_server_handshake_and_exchange_data() {
        let mut now = Instant::now();

        let client_cert = certificate::generate().unwrap();
        let server_cert = certificate::generate().unwrap();
        let client_fp = certificate::fingerprint(&client_cert).unwrap();
        let server_fp = certificate::fingerprint(&server_cert).unwrap();

        let mut client = DtlsLayer::new(
            addr(40010),
            addr(40011),
            ResolvedRole::Client,
            client_cert,
            server_fp,
            now,
        )
        .unwrap();
        let mut server = DtlsLayer::new(
            addr(40011),
            addr(40010),
            ResolvedRole::Server,
            server_cert,
            client_fp,
            now,
        )
        .unwrap();

        let mut client_done = false;
        let mut server_done = false;

        for _ in 0..2000 {
            let mut progressed = false;

            while let Some((data, to)) = client.poll_transmit() {
                progressed = true;
                assert_eq!(to, addr(40011));
                for event in server.handle_read(&data, now).unwrap() {
                    if matches!(event, EndpointEvent::HandshakeComplete) {
                        server_done = true;
                    }
                }
            }
            while let Some((data, to)) = server.poll_transmit() {
                progressed = true;
                assert_eq!(to, addr(40010));
                for event in client.handle_read(&data, now).unwrap() {
                    if matches!(event, EndpointEvent::HandshakeComplete) {
                        client_done = true;
                    }
                }
            }

            if client_done && server_done {
                break;
            }

            if !progressed {
                let next = [client.poll_timeout(), server.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                now = next
                    .unwrap_or(now + Duration::from_millis(20))
                    .max(now + Duration::from_millis(1));
                client.handle_timeout(now).unwrap();
                server.handle_timeout(now).unwrap();
            }
        }

        assert!(client_done, "client handshake never completed");
        assert!(server_done, "server handshake never completed");
    }

    #[test]
    fn a_lowercase_remote_fingerprint_still_verifies() {
        let mut now = Instant::now();

        let client_cert = certificate::generate().unwrap();
        let server_cert = certificate::generate().unwrap();
        let (algorithm, client_fp) = certificate::fingerprint(&client_cert).unwrap();
        let server_fp = certificate::fingerprint(&server_cert).unwrap();

        let mut client = DtlsLayer::new(
            addr(40012),
            addr(40013),
            ResolvedRole::Client,
            client_cert,
            server_fp,
            now,
        )
        .unwrap();
        let mut server = DtlsLayer::new(
            addr(40013),
            addr(40012),
            ResolvedRole::Server,
            server_cert,
            (algorithm, client_fp.to_lowercase()),
            now,
        )
        .unwrap();

        let mut client_done = false;
        let mut server_done = false;

        for _ in 0..2000 {
            let mut progressed = false;

            while let Some((data, to)) = client.poll_transmit() {
                progressed = true;
                assert_eq!(to, addr(40013));
                for event in server.handle_read(&data, now).unwrap() {
                    if matches!(event, EndpointEvent::HandshakeComplete) {
                        server_done = true;
                    }
                }
            }
            while let Some((data, to)) = server.poll_transmit() {
                progressed = true;
                assert_eq!(to, addr(40012));
                for event in client.handle_read(&data, now).unwrap() {
                    if matches!(event, EndpointEvent::HandshakeComplete) {
                        client_done = true;
                    }
                }
            }

            if client_done && server_done {
                break;
            }

            if !progressed {
                let next = [client.poll_timeout(), server.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                now = next
                    .unwrap_or(now + Duration::from_millis(20))
                    .max(now + Duration::from_millis(1));
                client.handle_timeout(now).unwrap();
                server.handle_timeout(now).unwrap();
            }
        }

        assert!(client_done, "client handshake never completed");
        assert!(server_done, "server handshake never completed");

        client.write(b"hello from client", now).unwrap();
        let mut delivered = None;
        for _ in 0..10 {
            if let Some((data, _)) = client.poll_transmit() {
                for event in server.handle_read(&data, now).unwrap() {
                    if let EndpointEvent::ApplicationData(msg) = event {
                        delivered = Some(msg);
                    }
                }
            }
        }
        assert_eq!(delivered.as_deref(), Some(&b"hello from client"[..]));
    }
}

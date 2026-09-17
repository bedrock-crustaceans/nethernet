//! Signaling over the HTTP endpoints exposed by NetherNet servers.
//!
//! Dedicated servers accept an SDP offer on `/v1/join/{network id}` and answer with the
//! SDP of the connection in the response body. As a request only carries a single
//! description, candidates are embedded in it instead of being signaled separately.

use crate::error::{NetherError, Result};
use crate::protocol::{Signal, SignalType};
use futures::Stream;
use nethernet::signaling::http::join;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use std::pin::Pin;
use std::sync::Once;
use std::time::Duration;
use tokio::sync::broadcast;
use url::Url;

/// Guards installation of the process-wide TLS provider.
static PROVIDER: Once = Once::new();

/// Signaling implementation for connecting to servers that expose an HTTP endpoint.
///
/// The network ID of a remote connection is the base URL of its endpoint, such as
/// `https://example.com:19132`, while the local network ID identifies this client to
/// the server.
pub struct HttpSignaling {
    network_id: String,
    client: Client,
    signal_tx: broadcast::Sender<Signal>,
}

impl HttpSignaling {
    /// Creates a signaling implementation using a default HTTP client.
    ///
    /// Installs the process-wide TLS provider if no other one has been installed yet,
    /// as building an HTTP client requires one.
    pub fn new(network_id: String) -> Result<Self> {
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| NetherError::Other(format!("create HTTP client: {}", e)))?;

        Ok(Self::with_client(network_id, client))
    }

    /// Creates a signaling implementation using the given HTTP client.
    ///
    /// Building a client requires a process-wide TLS provider, which
    /// [`HttpSignaling::new`] installs.
    pub fn with_client(network_id: String, client: Client) -> Self {
        let (signal_tx, _) = broadcast::channel(16);

        Self {
            network_id,
            client,
            signal_tx,
        }
    }

    /// Returns the URL an offer for the remote network is sent to.
    fn join_url(&self, network_id: &str) -> Result<Url> {
        let url = Url::parse(network_id)
            .map_err(|e| NetherError::Other(format!("parse network ID as URL: {}", e)))?;
        if !matches!(url.scheme(), "http" | "https") || url.port().is_none() {
            return Err(NetherError::Other(format!(
                "network ID must be a HTTP/HTTPS URL with a port: {}",
                network_id
            )));
        }

        url.join(&join::join_path(&self.network_id))
            .map_err(|e| NetherError::Other(format!("build join URL: {}", e)))
    }

    /// Sends the offer to the endpoint of the remote network and returns its answer.
    async fn join(&self, signal: &Signal) -> Result<String> {
        let response = self
            .client
            .post(self.join_url(&signal.network_id)?)
            .header(CONTENT_TYPE, join::CONTENT_TYPE)
            .header(USER_AGENT, join::CLIENT_USER_AGENT)
            .body(signal.data.clone())
            .send()
            .await
            .map_err(|e| NetherError::Other(format!("signal offer: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| NetherError::Other(format!("read answer: {}", e)))?;

        join::validate_join_response(status.as_u16(), &body).map_err(|e| match e {
            join::JoinResponseError::Rejected(code) => NetherError::Signaled(code),
            e => NetherError::Other(e.to_string()),
        })?;

        Ok(body)
    }
}

impl HttpSignaling {
    /// Signals an offer to the endpoint of the remote network and notifies its answer.
    ///
    /// Only offers are supported, as an answer is the response of the request carrying
    /// the offer and candidates are embedded in both.
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        match signal.signal_type {
            SignalType::Offer => {
                let answer = self.join(&signal).await?;
                let _ = self.signal_tx.send(Signal::answer(
                    signal.connection_id,
                    answer,
                    signal.network_id,
                ));
                Ok(())
            }
            SignalType::Error => Ok(()),
            signal_type => Err(NetherError::Other(format!(
                "{} is not supported over HTTP signaling",
                signal_type
            ))),
        }
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    pub fn network_id(&self) -> String {
        self.network_id.clone()
    }

    /// Always returns `true`, as a request carries a single description that must
    /// already contain every local candidate.
    pub fn disable_trickle_ice(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_is_built_from_the_network_id() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        assert_eq!(
            signaling.join_url("https://example.com:19132").unwrap(),
            Url::parse("https://example.com:19132/v1/join/1234").unwrap()
        );
    }

    #[test]
    fn join_url_rejects_network_ids_without_a_port() {
        let signaling = HttpSignaling::new("1234".to_string()).unwrap();

        assert!(signaling.join_url("https://example.com").is_err());
        assert!(signaling.join_url("5678").is_err());
    }
}

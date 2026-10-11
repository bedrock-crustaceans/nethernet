//! Cached Minecraft token signing keys.
use crate::error::{NetherError, Result};
use crate::util::tls::ensure_crypto_provider;
use nethernet::identity::{MINECRAFT_KEYS_URL, TokenTrust};
use nethernet::prelude::{JwkSet, MinecraftKeys};
use reqwest::Client;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MIN_INTERVAL: Duration = Duration::from_secs(60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const WATCH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// Key set shared between clones and refreshed over HTTP, at most once a minute.
///
/// [`trust`](Self::trust) hands out a [`TokenTrust`] over the same shared set, so
/// a refresh reaches servers already running. A background task refetches when a
/// token names a key the set lacks, and at least hourly, until every clone is dropped.
#[derive(Clone)]
pub struct Jwks {
    inner: Arc<Inner>,
}

struct Inner {
    url: String,
    client: Client,
    keys: MinecraftKeys,
    fetched_at: Mutex<Option<Instant>>,
}

impl Jwks {
    /// Fetches the keys from the Minecraft multiplayer endpoint.
    pub async fn minecraft() -> Result<Self> {
        Self::fetch(MINECRAFT_KEYS_URL, client(FETCH_TIMEOUT)?).await
    }

    pub async fn fetch(url: impl Into<String>, client: Client) -> Result<Self> {
        let jwks = Self {
            inner: Arc::new(Inner {
                url: url.into(),
                client,
                keys: MinecraftKeys::default(),
                fetched_at: Mutex::new(None),
            }),
        };

        jwks.refresh().await?;
        tokio::spawn(watch(Arc::downgrade(&jwks.inner)));
        Ok(jwks)
    }

    pub async fn keys(&self) -> JwkSet {
        self.inner.keys.snapshot()
    }

    /// Token trust over the shared keys, for validating Minecraft tokens.
    pub async fn trust(&self) -> TokenTrust {
        TokenTrust::Minecraft(self.inner.keys.clone())
    }

    pub async fn contains(&self, kid: &str) -> bool {
        self.inner.keys.snapshot().contains(kid)
    }

    /// Refetches the keys unless they were fetched less than 60 seconds ago.
    pub async fn refresh(&self) -> Result<()> {
        self.inner.refresh(MIN_INTERVAL).await
    }
}

impl Inner {
    async fn refresh(&self, min_interval: Duration) -> Result<()> {
        let mut fetched_at = self.fetched_at.lock().await;
        if fetched_at.is_some_and(|at| at.elapsed() < min_interval) {
            return Ok(());
        }

        let keys: JwkSet = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| NetherError::Other(format!("fetch keys: {}", e)))?
            .error_for_status()
            .map_err(|e| NetherError::Other(format!("fetch keys: {}", e)))?
            .json()
            .await
            .map_err(|e| NetherError::Other(format!("read keys: {}", e)))?;

        self.keys.replace(keys);
        *fetched_at = Some(Instant::now());
        Ok(())
    }

    async fn is_due(&self, max_age: Duration) -> bool {
        self.fetched_at
            .lock()
            .await
            .is_none_or(|at| at.elapsed() >= max_age)
    }

    /// Refetches if a token named an unpublished key or the keys are older than `max_age`.
    async fn refresh_if_needed(&self, min_interval: Duration, max_age: Duration) -> Result<()> {
        let missed = self.keys.take_missed();
        if !missed && !self.is_due(max_age).await {
            return Ok(());
        }
        let result = self.refresh(min_interval).await;
        if missed && (result.is_err() || !self.is_due(min_interval).await) {
            tracing::debug!(
                "a token named an unpublished key; refreshed: {}",
                result.is_ok()
            );
        }
        result
    }
}

async fn watch(inner: Weak<Inner>) {
    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;
        let Some(inner) = inner.upgrade() else {
            return;
        };
        if let Err(e) = inner.refresh_if_needed(MIN_INTERVAL, MAX_AGE).await {
            tracing::debug!("Minecraft key refresh failed: {e}");
        }
    }
}

fn client(timeout: Duration) -> Result<Client> {
    ensure_crypto_provider();
    Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| NetherError::Other(format!("create HTTP client: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nethernet::identity::{Assertion, Identity, Idp};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn a_key_server_that_never_answers_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/keys", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            Jwks::fetch(url, client(Duration::from_millis(200)).unwrap()),
        )
        .await;

        assert!(matches!(result, Ok(Err(_))), "the fetch did not give up");
    }

    async fn key_server(fetches: Arc<AtomicUsize>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/keys", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let kid = format!("key-{}", fetches.fetch_add(1, Ordering::SeqCst) + 1);
                let body =
                    format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"AQAB","e":"AQAB"}}]}}"#);
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        url
    }

    #[tokio::test]
    async fn a_missed_key_refetches_into_the_trust_already_handed_out() {
        let fetches = Arc::new(AtomicUsize::new(0));
        let url = key_server(fetches.clone()).await;
        let jwks = Jwks::fetch(url, client(FETCH_TIMEOUT).unwrap())
            .await
            .unwrap();
        let trust = jwks.trust().await;
        assert!(jwks.contains("key-1").await);

        jwks.inner
            .refresh_if_needed(Duration::ZERO, MAX_AGE)
            .await
            .unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "nothing was missed yet");

        assert!(trust.claims(&unknown_kid(), SystemTime::now()).is_err());
        jwks.inner
            .refresh_if_needed(Duration::ZERO, MAX_AGE)
            .await
            .unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        let TokenTrust::Minecraft(keys) = trust else {
            panic!("Minecraft trust expected");
        };
        assert!(keys.snapshot().contains("key-2"));
    }

    fn unknown_kid() -> Identity {
        Identity {
            idp: Idp {
                domain: "self".to_string(),
                protocol: "default".to_string(),
            },
            assertion: Assertion {
                token: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS05In0.eyJleHAiOjQxMDI0NDQ4MDB9.AA"
                    .to_string(),
                fingerprints: String::new(),
            },
        }
    }
}

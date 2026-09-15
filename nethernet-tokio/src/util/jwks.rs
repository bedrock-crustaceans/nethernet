//! The keys the Minecraft authorization service signs the tokens of its clients with.
//!
//! The sans-IO crate verifies a token against a key set it is handed, so fetching and
//! refreshing that set is what this module does. A set is refreshed when a token names a
//! key that is not in it yet, which is how a rotated key is picked up without a restart.

use crate::error::{NethernetError, Result};
use nethernet::identity::{MINECRAFT_KEYS_URL, TokenTrust};
use nethernet::prelude::JwkSet;
use reqwest::Client;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Shortest time between two fetches, so a flood of tokens naming keys that do not exist
/// cannot turn into a flood of requests.
const MIN_INTERVAL: Duration = Duration::from_secs(60);

/// The keys of an issuer, refreshed when a token names one that is not held yet.
#[derive(Clone)]
pub struct Jwks {
    url: String,
    client: Client,
    state: Arc<RwLock<State>>,
}

struct State {
    keys: JwkSet,
    fetched: Option<Instant>,
}

impl Jwks {
    /// Fetches the keys of the Minecraft authorization service.
    pub async fn minecraft() -> Result<Self> {
        Self::fetch(MINECRAFT_KEYS_URL, Client::new()).await
    }

    /// Fetches the keys published at the given URL.
    pub async fn fetch(url: impl Into<String>, client: Client) -> Result<Self> {
        let jwks = Self {
            url: url.into(),
            client,
            state: Arc::new(RwLock::new(State {
                keys: JwkSet::default(),
                fetched: None,
            })),
        };

        jwks.refresh().await?;
        Ok(jwks)
    }

    /// The keys as they were last fetched.
    pub fn keys(&self) -> JwkSet {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .clone()
    }

    /// The trust policy a retail client is validated against.
    pub fn trust(&self) -> TokenTrust {
        TokenTrust::Minecraft(self.keys())
    }

    /// Reports whether the key with the given ID is held.
    pub fn contains(&self, kid: &str) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .contains(kid)
    }

    /// Fetches the keys again, unless they were fetched a moment ago.
    pub async fn refresh(&self) -> Result<()> {
        {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            if state
                .fetched
                .is_some_and(|fetched| fetched.elapsed() < MIN_INTERVAL)
            {
                return Ok(());
            }
        }

        let keys: JwkSet = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| NethernetError::Other(format!("fetch keys: {}", e)))?
            .error_for_status()
            .map_err(|e| NethernetError::Other(format!("fetch keys: {}", e)))?
            .json()
            .await
            .map_err(|e| NethernetError::Other(format!("read keys: {}", e)))?;

        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.keys = keys;
        state.fetched = Some(Instant::now());

        Ok(())
    }
}

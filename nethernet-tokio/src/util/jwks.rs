//! The keys the Minecraft authorization service signs the tokens of its clients with.
//!
//! The sans-IO crate verifies a token against a key set it is handed, so fetching and
//! refreshing that set is what this module does. A set is refreshed when a token names a
//! key that is not in it yet, which is how a rotated key is picked up without a restart.

use crate::error::{NethernetError, Result};
use nethernet::identity::{MINECRAFT_KEYS_URL, TokenTrust};
use nethernet::prelude::JwkSet;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// Shortest time between two fetches, so a flood of tokens naming keys that do not exist
/// cannot turn into a flood of requests.
const MIN_INTERVAL: Duration = Duration::from_secs(60);

enum Command {
    Keys(oneshot::Sender<JwkSet>),
    Contains(String, oneshot::Sender<bool>),
    FetchedAt(oneshot::Sender<Option<Instant>>),
    Store(Box<JwkSet>, Instant),
}

/// The keys of an issuer, refreshed when a token names one that is not held yet.
///
/// The keys themselves live only inside a background task; every accessor here sends it
/// a `Command` and awaits the reply, rather than sharing the cache behind a lock. The
/// task ends naturally once every clone of the handle is dropped.
#[derive(Clone)]
pub struct Jwks {
    url: String,
    client: Client,
    commands: mpsc::UnboundedSender<Command>,
}

impl Jwks {
    /// Fetches the keys of the Minecraft authorization service.
    pub async fn minecraft() -> Result<Self> {
        Self::fetch(MINECRAFT_KEYS_URL, Client::new()).await
    }

    /// Fetches the keys published at the given URL.
    pub async fn fetch(url: impl Into<String>, client: Client) -> Result<Self> {
        let (commands, command_rx) = mpsc::unbounded_channel();
        tokio::spawn(Self::drive(command_rx));

        let jwks = Self {
            url: url.into(),
            client,
            commands,
        };

        jwks.refresh().await?;
        Ok(jwks)
    }

    async fn drive(mut commands: mpsc::UnboundedReceiver<Command>) {
        let mut keys = JwkSet::default();
        let mut fetched_at = None;

        while let Some(command) = commands.recv().await {
            match command {
                Command::Keys(reply) => {
                    let _ = reply.send(keys.clone());
                }
                Command::Contains(kid, reply) => {
                    let _ = reply.send(keys.contains(&kid));
                }
                Command::FetchedAt(reply) => {
                    let _ = reply.send(fetched_at);
                }
                Command::Store(new_keys, at) => {
                    keys = *new_keys;
                    fetched_at = Some(at);
                }
            }
        }
    }

    /// The keys as they were last fetched.
    pub async fn keys(&self) -> JwkSet {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.commands.send(Command::Keys(reply_tx)).is_err() {
            return JwkSet::default();
        }
        reply_rx.await.unwrap_or_default()
    }

    /// The trust policy a retail client is validated against.
    pub async fn trust(&self) -> TokenTrust {
        TokenTrust::Minecraft(self.keys().await)
    }

    /// Reports whether the key with the given ID is held.
    pub async fn contains(&self, kid: &str) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .commands
            .send(Command::Contains(kid.to_string(), reply_tx))
            .is_err()
        {
            return false;
        }
        reply_rx.await.unwrap_or(false)
    }

    /// Fetches the keys again, unless they were fetched a moment ago.
    pub async fn refresh(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.commands.send(Command::FetchedAt(reply_tx)).is_ok()
            && reply_rx
                .await
                .ok()
                .flatten()
                .is_some_and(|fetched| fetched.elapsed() < MIN_INTERVAL)
        {
            return Ok(());
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

        let _ = self
            .commands
            .send(Command::Store(Box::new(keys), Instant::now()));

        Ok(())
    }
}

use crate::error::{NetherError, Result};
use nethernet::identity::{MINECRAFT_KEYS_URL, TokenTrust};
use nethernet::prelude::JwkSet;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

const MIN_INTERVAL: Duration = Duration::from_secs(60);

enum Command {
    Keys(oneshot::Sender<JwkSet>),
    Contains(String, oneshot::Sender<bool>),
    FetchedAt(oneshot::Sender<Option<Instant>>),
    Store(Box<JwkSet>, Instant),
}

#[derive(Clone)]
pub struct Jwks {
    url: String,
    client: Client,
    commands: mpsc::UnboundedSender<Command>,
}

impl Jwks {
    pub async fn minecraft() -> Result<Self> {
        Self::fetch(MINECRAFT_KEYS_URL, Client::new()).await
    }

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

    pub async fn keys(&self) -> JwkSet {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.commands.send(Command::Keys(reply_tx)).is_err() {
            return JwkSet::default();
        }
        reply_rx.await.unwrap_or_default()
    }

    pub async fn trust(&self) -> TokenTrust {
        TokenTrust::Minecraft(self.keys().await)
    }

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
            .map_err(|e| NetherError::Other(format!("fetch keys: {}", e)))?
            .error_for_status()
            .map_err(|e| NetherError::Other(format!("fetch keys: {}", e)))?
            .json()
            .await
            .map_err(|e| NetherError::Other(format!("read keys: {}", e)))?;

        let _ = self
            .commands
            .send(Command::Store(Box::new(keys), Instant::now()));

        Ok(())
    }
}

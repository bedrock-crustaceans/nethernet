//! Settings for the HTTP signaler.
use crate::identity::TokenTrust;
use crate::util::ip_range::IpRangeSet;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpSignalerConfig {
    /// Connections allowed per peer address; trusted proxies are not counted.
    pub max_connections_per_address: usize,

    /// Joins waiting for an answer beyond this limit get 503.
    pub max_pending_joins: usize,

    /// Time to wait for an answer before replying 504.
    pub answer_timeout: Duration,

    /// Peers whose `x-forwarded-for` is believed for the client address.
    pub trusted_proxies: IpRangeSet,

    /// Addresses announced in answers in place of all gathered host candidates; empty announces all.
    pub advertised_addresses: Vec<String>,

    /// How offers are authenticated, with failures answered 401; `None` skips validation.
    /// The default accepts any unexpired token.
    pub token_trust: Option<TokenTrust>,

    /// Whether GET `/v1/join` returns the server data as JSON.
    pub serve_motd: bool,
}

impl Default for HttpSignalerConfig {
    fn default() -> Self {
        Self {
            max_connections_per_address: 16,
            max_pending_joins: 64,
            answer_timeout: Duration::from_secs(10),
            trusted_proxies: IpRangeSet::empty(),
            advertised_addresses: Vec::new(),
            token_trust: Some(TokenTrust::Any),
            serve_motd: true,
        }
    }
}

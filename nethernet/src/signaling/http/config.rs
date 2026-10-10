use crate::identity::TokenTrust;
use crate::util::ip_range::IpRangeSet;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpSignalerConfig {
    pub max_connections_per_address: usize,

    pub max_pending_joins: usize,

    pub answer_timeout: Duration,

    pub trusted_proxies: IpRangeSet,

    pub advertised_addresses: Vec<String>,

    pub token_trust: Option<TokenTrust>,

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

//! Options of the HTTP endpoint servers expose.

use crate::identity::TokenTrust;
use crate::util::ip_range::IpRangeSet;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpSignalerConfig {
    /// How many connections one address may hold open at once.
    ///
    /// Anyone can reach this endpoint, and a kept connection costs a socket until it goes
    /// idle, so without a cap a single peer can hold as many as the host has descriptors.
    /// A trusted proxy is exempt, since every client behind it shares its address and
    /// counting them together would throttle all of them at once.
    pub max_connections_per_address: usize,

    /// How many joins may wait for an answer at once. The cap is applied before the
    /// identity of an offer is validated, so a flood cannot make the host verify its way
    /// through the limit.
    pub max_pending_joins: usize,

    /// How long a join waits for the answer of the transport.
    pub answer_timeout: Duration,

    /// The proxies allowed to speak for a client, which decides whose forwarded address
    /// is believed.
    pub trusted_proxies: IpRangeSet,

    /// The addresses that may be announced in an answer, empty to announce every
    /// candidate that was gathered.
    pub advertised_addresses: Vec<String>,

    /// Who is trusted to have signed the token of an offer, or [`None`] to accept offers
    /// that carry no identity at all.
    ///
    /// [`TokenTrust::Minecraft`] is what a retail client presents, and it needs the keys
    /// of the authorization service, which the caller fetches and refreshes.
    pub token_trust: Option<TokenTrust>,

    /// Whether the status endpoint answers with the advertised server data.
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

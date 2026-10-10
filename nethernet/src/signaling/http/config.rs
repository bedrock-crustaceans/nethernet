//! Options of the HTTP endpoint servers expose.

use crate::identity::TokenTrust;
use crate::util::endpoint;
use crate::util::ip_range::IpRangeSet;
use std::net::SocketAddr;
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

    /// Whether a PROXY protocol header is read off the front of a connection from a
    /// trusted proxy.
    pub proxy_protocol: bool,

    /// The addresses that may be announced in an answer, empty to announce every
    /// candidate that was gathered.
    pub advertised_addresses: Vec<String>,

    /// Who is trusted to have signed the token of an offer, or [`None`] to accept offers
    /// that carry no identity at all.
    ///
    /// This is the only place offers over HTTP are validated: a refused offer is answered
    /// with 401, and the transport does not validate it again.
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
            proxy_protocol: false,
            advertised_addresses: Vec::new(),
            token_trust: Some(TokenTrust::Any),
            serve_motd: true,
        }
    }
}

impl HttpSignalerConfig {
    /// Whether a connection from this peer starts with a PROXY protocol header, which is
    /// so only when the option is on and the peer is a trusted proxy. An IPv4 address
    /// mapped into IPv6 counts as the IPv4 address it carries.
    pub fn reads_proxy_header(&self, peer: SocketAddr) -> bool {
        self.proxy_protocol
            && self
                .trusted_proxies
                .contains(endpoint::normalize(peer.ip()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_config(proxy_protocol: bool) -> HttpSignalerConfig {
        HttpSignalerConfig {
            trusted_proxies: IpRangeSet::parse(["10.0.0.0/8"]),
            proxy_protocol,
            ..Default::default()
        }
    }

    #[test]
    fn a_mapped_trusted_proxy_sends_a_proxy_header() {
        let config = proxy_config(true);
        assert!(config.reads_proxy_header("[::ffff:10.0.0.2]:1000".parse().unwrap()));
        assert!(config.reads_proxy_header("10.0.0.2:1000".parse().unwrap()));
    }

    #[test]
    fn a_disabled_proxy_protocol_reads_no_header() {
        let config = proxy_config(false);
        assert!(!config.reads_proxy_header("10.0.0.2:1000".parse().unwrap()));
    }

    #[test]
    fn an_untrusted_peer_reads_no_header() {
        let config = proxy_config(true);
        assert!(!config.reads_proxy_header("203.0.113.5:1000".parse().unwrap()));
        assert!(!config.reads_proxy_header("[::ffff:203.0.113.5]:1000".parse().unwrap()));
    }
}

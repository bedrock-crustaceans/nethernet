//! Parsing and rewriting of `a=candidate` lines in SDP.
use crate::util::endpoint;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

const ATTRIBUTE_PREFIX: &str = "a=candidate:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CandidateLineError {
    #[error("the candidate line has fewer than eight tokens")]
    TooFewTokens,
    #[error("the seventh token of the candidate line is not `typ`")]
    MissingTypeKeyword,
    #[error("the candidate type is not host, srflx, prflx or relay")]
    UnknownKind,
    #[error("the candidate port is not a port number")]
    InvalidPort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Host,
    Srflx,
    Prflx,
    Relay,
}

impl CandidateKind {
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::Srflx),
            "prflx" => Some(Self::Prflx),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }

    pub fn is_reflexive_or_relayed(self) -> bool {
        self != Self::Host
    }
}

/// A parsed `a=candidate:` line (RFC 5245 section 15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateLine<'a> {
    transport: &'a str,
    address: &'a str,
    port: u16,
    kind: CandidateKind,
}

impl<'a> CandidateLine<'a> {
    const MAX_INFERRED: usize = 8;

    const INFERRED_PRIORITY: u32 = 1677721855;

    const INFERRED_FOUNDATION: u32 = 90_000_000;

    const TRANSLATED_PRIORITY: u32 = (100 << 24) | (65535 << 8) | 255;

    const TRANSLATED_FOUNDATION: u32 = 80_000_000;

    pub fn address(&self) -> &'a str {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn kind(&self) -> CandidateKind {
        self.kind
    }

    pub fn transport(&self) -> &'a str {
        self.transport
    }

    fn is_udp(&self) -> bool {
        self.transport.eq_ignore_ascii_case("udp")
    }

    fn inferred(index: usize, source: IpAddr, port: u16) -> String {
        format!(
            "candidate:{} 1 UDP {} {} {} typ srflx raddr 0.0.0.0 rport 0",
            Self::INFERRED_FOUNDATION + index as u32,
            Self::INFERRED_PRIORITY,
            source,
            port
        )
    }

    fn translated(&self, foundation: u32, address: &str) -> String {
        format!(
            "{ATTRIBUTE_PREFIX}{} 1 {} {} {} {} typ srflx raddr {} rport {}",
            foundation,
            self.transport,
            Self::TRANSLATED_PRIORITY,
            address,
            self.port,
            self.address,
            self.port
        )
    }
}

impl<'a> TryFrom<&'a str> for CandidateLine<'a> {
    type Error = CandidateLineError;

    fn try_from(line: &'a str) -> Result<Self, Self::Error> {
        let tokens: Vec<&str> = line.split(' ').collect();
        if tokens.len() < 8 {
            return Err(CandidateLineError::TooFewTokens);
        }
        if tokens[6] != "typ" {
            return Err(CandidateLineError::MissingTypeKeyword);
        }
        let kind = CandidateKind::from_token(tokens[7]).ok_or(CandidateLineError::UnknownKind)?;
        let port = tokens[5]
            .parse()
            .map_err(|_| CandidateLineError::InvalidPort)?;

        Ok(Self {
            transport: tokens[2],
            address: tokens[4],
            port,
            kind,
        })
    }
}

/// True when a host candidate has a public or private address rather than loopback or unusable.
pub fn has_routable_host_candidate(sdp: &str) -> bool {
    candidates(sdp).any(|candidate| {
        candidate.kind() == CandidateKind::Host
            && endpoint::parse(candidate.address()).is_some_and(endpoint::routable)
    })
}

/// Reflexive candidates pairing the signaling source address with the offer's host UDP ports, at most eight.
/// Empty when the source is not routable or the offer already has reflexive or relayed candidates.
pub fn inferred_peer_candidates(sdp: &str, signaled_from: Option<SocketAddr>) -> Vec<String> {
    let Some(from) = signaled_from.map(|addr| endpoint::normalize(addr.ip())) else {
        return Vec::new();
    };
    if !endpoint::routable(from) {
        return Vec::new();
    }

    let mut ports: Vec<u16> = Vec::new();
    for candidate in candidates(sdp) {
        if candidate.kind().is_reflexive_or_relayed() {
            return Vec::new();
        }
        if candidate.is_udp()
            && ports.len() < CandidateLine::MAX_INFERRED
            && !ports.contains(&candidate.port())
        {
            ports.push(candidate.port());
        }
    }

    ports
        .into_iter()
        .enumerate()
        .map(|(index, port)| CandidateLine::inferred(index, from, port))
        .collect()
}

/// Keeps only host candidates on `allowed` addresses and adds translated candidates for allowed addresses not gathered.
/// Returns the SDP unchanged when `allowed` is empty or nothing matches.
pub fn with_advertised_candidates(sdp: &str, allowed: &[String]) -> String {
    if allowed.is_empty() {
        return sdp.to_string();
    }

    let lines: Vec<&str> = sdp
        .split(['\r', '\n'])
        .filter(|line| !line.is_empty())
        .collect();

    let mut gathered: HashSet<String> = HashSet::new();
    let mut hosts: Vec<CandidateLine> = Vec::new();
    for candidate in candidates(sdp) {
        gathered.insert(normalized(candidate.address()));
        if candidate.kind() == CandidateKind::Host && candidate.is_udp() {
            hosts.push(candidate);
        }
    }

    let mut held: HashSet<String> = HashSet::new();
    let mut foreign: Vec<String> = Vec::new();
    for address in allowed {
        let address = normalized(address);
        if gathered.contains(&address) {
            held.insert(address);
        } else {
            foreign.push(address);
        }
    }
    foreign.sort();
    hosts.sort_by_key(|host| !held.contains(&normalized(host.address())));

    let mut translated = translated_candidates(&hosts, &foreign);
    if held.is_empty() && translated.is_empty() {
        tracing::warn!(
            "none of the gathered candidates match the advertised addresses, announcing all of them instead"
        );
        return sdp.to_string();
    }

    let mut out = String::with_capacity(sdp.len());
    let mut seen_candidates = false;
    for line in &lines {
        if line.starts_with(ATTRIBUTE_PREFIX) {
            seen_candidates = true;
            if !held.is_empty() {
                let kept = CandidateLine::try_from(*line).is_ok_and(|candidate| {
                    candidate.kind().is_reflexive_or_relayed()
                        || held.contains(&normalized(candidate.address()))
                });
                if !kept {
                    continue;
                }
            }
        } else if seen_candidates && !translated.is_empty() {
            for candidate in translated.drain(..) {
                out.push_str(&candidate);
                out.push_str("\r\n");
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    for candidate in translated.drain(..) {
        out.push_str(&candidate);
        out.push_str("\r\n");
    }
    out
}

fn translated_candidates(hosts: &[CandidateLine], foreign: &[String]) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut emitted: HashSet<(&str, u16)> = HashSet::new();
    let mut foundation = CandidateLine::TRANSLATED_FOUNDATION;

    for address in foreign {
        let Some(target) = endpoint::parse(address) else {
            tracing::warn!(
                "advertised address {address} is not an IP literal, so it cannot be announced"
            );
            continue;
        };

        for host in hosts {
            let same_family = matches!(
                (target, endpoint::parse(host.address())),
                (IpAddr::V4(_), Some(IpAddr::V4(_))) | (IpAddr::V6(_), Some(IpAddr::V6(_)))
            );
            if !same_family || !emitted.insert((address.as_str(), host.port())) {
                continue;
            }

            candidates.push(host.translated(foundation, address));
            foundation += 1;
        }
    }

    candidates
}

fn candidates(sdp: &str) -> impl Iterator<Item = CandidateLine<'_>> {
    sdp.split(['\r', '\n'])
        .filter(|line| line.starts_with(ATTRIBUTE_PREFIX))
        .filter_map(|line| CandidateLine::try_from(line).ok())
}

fn normalized(address: &str) -> String {
    endpoint::parse(address).map_or_else(|| address.to_string(), |literal| literal.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host generation 0\r\n\
        a=candidate:2 1 udp 2130706431 10.0.0.5 54322 typ host generation 0\r\n\
        a=ice-ufrag:abcd\r\n";

    #[test]
    fn a_candidate_line_exposes_its_address_port_and_kind() {
        let line = CandidateLine::try_from(
            "a=candidate:2 1 udp 1694498815 203.0.113.1 40000 typ srflx raddr 192.168.1.10 rport 54321",
        )
        .unwrap();

        assert_eq!(line.address(), "203.0.113.1");
        assert_eq!(line.port(), 40000);
        assert_eq!(line.kind(), CandidateKind::Srflx);
        assert_eq!(line.transport(), "udp");
    }

    #[test]
    fn malformed_candidate_lines_name_what_is_wrong() {
        assert_eq!(
            CandidateLine::try_from("a=candidate:1 1 udp"),
            Err(CandidateLineError::TooFewTokens)
        );
        assert_eq!(
            CandidateLine::try_from("a=candidate:1 1 udp 1 1.2.3.4 5 TYP host"),
            Err(CandidateLineError::MissingTypeKeyword)
        );
        assert_eq!(
            CandidateLine::try_from("a=candidate:1 1 udp 1 1.2.3.4 5 typ HOST"),
            Err(CandidateLineError::UnknownKind)
        );
        assert_eq!(
            CandidateLine::try_from("a=candidate:1 1 udp 1 1.2.3.4 http typ host"),
            Err(CandidateLineError::InvalidPort)
        );
    }

    #[test]
    fn private_host_candidates_count_as_routable() {
        assert!(has_routable_host_candidate(OFFER));
    }

    #[test]
    fn link_local_host_candidates_do_not() {
        let sdp = "a=candidate:1 1 udp 2130706431 169.254.4.4 54321 typ host generation 0\r\n";

        assert!(!has_routable_host_candidate(sdp));
    }

    #[test]
    fn a_candidate_is_inferred_for_every_gathered_port() {
        let inferred =
            inferred_peer_candidates(OFFER, Some("93.184.216.34:19132".parse().unwrap()));

        assert_eq!(
            inferred,
            vec![
                "candidate:90000000 1 UDP 1677721855 93.184.216.34 54321 typ srflx raddr 0.0.0.0 rport 0",
                "candidate:90000001 1 UDP 1677721855 93.184.216.34 54322 typ srflx raddr 0.0.0.0 rport 0",
            ]
        );
    }

    #[test]
    fn nothing_is_inferred_for_a_peer_that_gathered_a_reflexive_candidate() {
        let sdp = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host\r\n\
            a=candidate:2 1 udp 1694498815 93.184.216.34 40000 typ srflx raddr 192.168.1.10 rport 54321\r\n";

        assert!(
            inferred_peer_candidates(sdp, Some("93.184.216.34:19132".parse().unwrap())).is_empty()
        );
    }

    #[test]
    fn nothing_is_inferred_without_a_routable_source() {
        assert!(inferred_peer_candidates(OFFER, None).is_empty());
        assert!(
            inferred_peer_candidates(OFFER, Some("127.0.0.1:19132".parse().unwrap())).is_empty()
        );
    }

    #[test]
    fn only_advertised_candidates_are_announced() {
        let filtered = with_advertised_candidates(OFFER, &["192.168.1.10".to_string()]);

        assert!(filtered.contains("192.168.1.10"));
        assert!(!filtered.contains("10.0.0.5"));
        assert!(filtered.contains("a=ice-ufrag:abcd"));
    }

    #[test]
    fn a_foreign_address_is_announced_as_a_translated_candidate() {
        let translated = with_advertised_candidates(OFFER, &["203.0.113.1".to_string()]);

        assert!(translated.contains("192.168.1.10"));
        assert!(translated.contains("10.0.0.5"));
        assert!(translated.contains(
            "a=candidate:80000000 1 udp 1694498815 203.0.113.1 54321 typ srflx \
             raddr 192.168.1.10 rport 54321"
        ));
        assert!(translated.contains(
            "a=candidate:80000001 1 udp 1694498815 203.0.113.1 54322 typ srflx \
             raddr 10.0.0.5 rport 54322"
        ));
    }

    #[test]
    fn a_description_that_would_lose_every_candidate_and_cannot_be_translated_is_left_alone() {
        let filtered = with_advertised_candidates(OFFER, &["not-an-ip-literal".to_string()]);

        assert_eq!(filtered, OFFER);
    }

    #[test]
    fn a_held_host_is_preferred_as_the_translation_base_for_its_family() {
        let translated = with_advertised_candidates(
            OFFER,
            &["192.168.1.10".to_string(), "203.0.113.1".to_string()],
        );

        let from_held = translated.find("raddr 192.168.1.10").unwrap();
        let from_other = translated.find("raddr 10.0.0.5").unwrap();
        assert!(from_held < from_other, "{translated}");
    }

    const PUBLIC_SOURCE: &str = "93.184.216.34:19132";

    fn inferred_from_public(sdp: &str) -> Vec<String> {
        inferred_peer_candidates(sdp, Some(PUBLIC_SOURCE.parse().unwrap()))
    }

    #[test]
    fn a_host_candidate_with_related_extras_is_still_a_host() {
        let sdp = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host raddr 0.0.0.0 rport 0 generation 0\r\n";

        assert!(has_routable_host_candidate(sdp));
        assert_eq!(
            inferred_from_public(sdp),
            vec![
                "candidate:90000000 1 UDP 1677721855 93.184.216.34 54321 typ srflx raddr 0.0.0.0 rport 0"
            ]
        );
    }

    #[test]
    fn tcp_host_candidates_count_as_hosts_but_infer_no_ports() {
        let sdp = "a=candidate:1 1 tcp 1518280447 192.168.1.10 9 typ host tcptype active\r\n";

        assert!(has_routable_host_candidate(sdp));
        assert!(inferred_from_public(sdp).is_empty());
    }

    #[test]
    fn a_line_with_fewer_than_eight_tokens_is_ignored() {
        let sdp = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ\r\n";

        assert!(!has_routable_host_candidate(sdp));
        assert!(inferred_from_public(sdp).is_empty());
    }

    #[test]
    fn ipv6_host_candidates_are_accepted_and_every_udp_port_is_inferred() {
        let sdp = "a=candidate:1 1 udp 2130706431 2606:4700::2 54321 typ host\r\n\
            a=candidate:2 1 udp 2130706431 fe80::1 54322 typ host\r\n";

        assert!(has_routable_host_candidate(sdp));
        assert!(!has_routable_host_candidate(
            "a=candidate:2 1 udp 2130706431 fe80::1 54322 typ host\r\n"
        ));
        assert_eq!(
            inferred_peer_candidates(sdp, Some("[2606:4700::1]:19132".parse().unwrap())),
            vec![
                "candidate:90000000 1 UDP 1677721855 2606:4700::1 54321 typ srflx raddr 0.0.0.0 rport 0",
                "candidate:90000001 1 UDP 1677721855 2606:4700::1 54322 typ srflx raddr 0.0.0.0 rport 0",
            ]
        );
    }

    #[test]
    fn mdns_host_candidates_are_not_routable_but_still_give_ports() {
        let sdp = "a=candidate:1 1 udp 2130706431 3f2a9c1e-77aa-4b1d-9e3c-0a1b2c3d4e5f.local 54321 typ host\r\n";

        assert!(!has_routable_host_candidate(sdp));
        assert_eq!(inferred_from_public(sdp).len(), 1);
    }

    #[test]
    fn mdns_candidates_are_dropped_when_other_addresses_are_held() {
        let sdp = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host\r\n\
            a=candidate:2 1 udp 2130706431 abcd.local 54322 typ host\r\n";

        let filtered = with_advertised_candidates(sdp, &["192.168.1.10".to_string()]);

        assert!(filtered.contains("192.168.1.10"));
        assert!(!filtered.contains("abcd.local"));
    }

    #[test]
    fn a_srflx_candidate_with_related_address_stops_inference_and_survives_filtering() {
        let sdp = "a=candidate:1 1 udp 2130706431 10.0.0.5 54321 typ host\r\n\
            a=candidate:2 1 udp 1694498815 203.0.113.1 40000 typ srflx raddr 10.0.0.5 rport 54321\r\n";

        assert!(inferred_from_public(sdp).is_empty());
        let filtered = with_advertised_candidates(sdp, &["192.168.1.10".to_string()]);
        assert!(filtered.contains("typ srflx raddr 10.0.0.5 rport 54321"));
    }

    #[test]
    fn transport_is_case_insensitive_but_the_typ_keyword_and_kind_are_not() {
        let upper_transport = "a=candidate:1 1 UDP 2130706431 192.168.1.10 54321 typ host\r\n";
        let upper_keyword = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 TYP host\r\n";
        let upper_kind = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ HOST\r\n";

        assert_eq!(inferred_from_public(upper_transport).len(), 1);
        assert!(has_routable_host_candidate(upper_transport));
        assert!(!has_routable_host_candidate(upper_keyword));
        assert!(!has_routable_host_candidate(upper_kind));
        assert!(inferred_from_public(upper_keyword).is_empty());
        assert!(inferred_from_public(upper_kind).is_empty());
    }

    #[test]
    fn doubled_spaces_make_a_line_unparseable() {
        let sdp = "a=candidate:1 1 udp 2130706431  192.168.1.10 54321 typ host\r\n";

        assert!(!has_routable_host_candidate(sdp));
        assert!(inferred_from_public(sdp).is_empty());
    }

    #[test]
    fn reflexive_and_relayed_candidates_are_never_dropped() {
        let sdp = "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host\r\n\
            a=candidate:2 1 udp 1694498815 203.0.113.1 40000 typ srflx raddr 192.168.1.10 rport 54321\r\n";

        let filtered = with_advertised_candidates(sdp, &["192.168.1.10".to_string()]);

        assert!(filtered.contains("typ host"));
        assert!(filtered.contains("typ srflx"));
    }
}

//! Helpers for the candidate lines of the descriptions exchanged during signaling.

use crate::util::endpoint;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

const ATTRIBUTE_PREFIX: &str = "a=candidate:";

/// How many ports are guessed at for one peer. A peer gathers one port per interface it
/// holds, so a handful covers any real client, and the offer deciding how many packets
/// leave here is not something a peer should get to choose.
const MAX_INFERRED_CANDIDATES: usize = 8;

/// Priority announced for an inferred candidate, matching what a peer would announce for
/// a server reflexive candidate of its own.
const INFERRED_PRIORITY: u32 = 1677721855;

/// Foundation the inferred candidates are numbered from.
const INFERRED_FOUNDATION: u32 = 90_000_000;

/// The connection address of a candidate line, or [`None`] if it has none.
///
/// The grammar of RFC 5245 section 15.1 puts the address in the fifth token, after the
/// foundation, component, transport and priority.
pub fn address(candidate: &str) -> Option<&str> {
    candidate.split(' ').nth(4).filter(|part| !part.is_empty())
}

/// Reports whether a description holds a host candidate at a routable address.
///
/// A host that gathered one is reachable as the protocol expects, and needs none of the
/// guessing [`inferred_peer_candidates`] does.
pub fn has_routable_host_candidate(sdp: &str) -> bool {
    lines(sdp).any(|line| {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() < 8 || parts[6] != "typ" || parts[7] != "host" {
            return false;
        }

        address(line)
            .and_then(endpoint::parse)
            .is_some_and(endpoint::routable)
    })
}

/// Candidates for the address a peer signaled from, one per port it gathered locally.
///
/// A peer that holds no reflexive candidate of its own offers nothing a host on another
/// network can reach, and its own checks die on the first NAT they meet. Its public
/// address is known anyway, because it just signaled from it, and consumer NATs usually
/// keep the port a socket already uses. Checking there costs a few packets, and if it
/// does map that way the check opens the path in both directions.
///
/// Nothing is inferred for a peer that already carries a reflexive or relayed candidate,
/// or that signaled from an address on this network, since there is a real path in both
/// cases. The candidates are returned in the `candidate:` form signaled over the wire.
pub fn inferred_peer_candidates(sdp: &str, signaled_from: Option<SocketAddr>) -> Vec<String> {
    let Some(from) = signaled_from.map(|addr| endpoint::normalize(addr.ip())) else {
        return Vec::new();
    };
    if !endpoint::routable(from) {
        return Vec::new();
    }

    let mut ports: Vec<&str> = Vec::new();
    for line in lines(sdp) {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() < 8 || parts[6] != "typ" {
            continue;
        }
        if parts[7] != "host" {
            // The peer can already be reached without guessing
            return Vec::new();
        }
        if parts[2].eq_ignore_ascii_case("udp")
            && ports.len() < MAX_INFERRED_CANDIDATES
            && !ports.contains(&parts[5])
        {
            ports.push(parts[5]);
        }
    }

    let host = host_literal(from);
    ports
        .into_iter()
        .enumerate()
        .map(|(index, port)| {
            format!(
                "candidate:{} 1 UDP {} {} {} typ srflx raddr 0.0.0.0 rport 0",
                INFERRED_FOUNDATION + index as u32,
                INFERRED_PRIORITY,
                host,
                port
            )
        })
        .collect()
}

/// Priority a translated candidate is announced at: RFC 8445 §5.1.2.1's server-reflexive
/// preference, below any host.
const TRANSLATED_PRIORITY: u32 = (100 << 24) | (65535 << 8) | 255;

/// Foundation the translated candidates are numbered from.
const TRANSLATED_FOUNDATION: u32 = 80_000_000;

/// Drops every host candidate whose address is not in `allowed`, and, for an allowed
/// address this host never actually gathered, announces it as a server-reflexive
/// candidate translated from a host candidate of the same address family.
///
/// ICE gathers a candidate on every interface it can see, which on a host network
/// includes container and overlay addresses that are unreachable from outside. Each one
/// costs the remote connection a round of connectivity checks before it gives up, so a
/// host that knows which of its addresses are reachable can announce only those.
/// Reflexive and relayed candidates always stay, since they already describe what the
/// outside sees rather than an interface.
///
/// The translation covers a server sitting behind a NAT or a port forward that never
/// shows up in what ICE gathers locally, but that a peer can still reach: the port a
/// forward maps to is normally the same one the host candidate uses, since consumer NATs
/// and forwards alike preserve it. If nothing would be left - no held candidate and
/// nothing to translate - the description is returned untouched, since no candidates at
/// all can never connect.
pub fn with_advertised_candidates(sdp: &str, allowed: &[String]) -> String {
    if allowed.is_empty() {
        return sdp.to_string();
    }

    let lines: Vec<&str> = sdp
        .split(['\r', '\n'])
        .filter(|line| !line.is_empty())
        .collect();

    let mut gathered: HashSet<String> = HashSet::new();
    let mut hosts: Vec<Vec<&str>> = Vec::new();
    for line in &lines {
        if !line.starts_with(ATTRIBUTE_PREFIX) {
            continue;
        }
        if let Some(address) = address(line) {
            gathered.insert(normalized(address));
        }
        let parts: Vec<&str> = line.split(' ').collect();
        if is_host_candidate(line) && parts.get(2).is_some_and(|p| p.eq_ignore_ascii_case("udp")) {
            hosts.push(parts);
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
    // A held host is the more honest base for a translation, so it goes first for its family.
    hosts.sort_by_key(|host| !held.contains(&normalized(host[4])));

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
            if !held.is_empty() && !is_reflexive_or_relayed(line) {
                match address(line) {
                    Some(address) if held.contains(&normalized(address)) => {}
                    _ => continue,
                }
            }
        } else if seen_candidates && !translated.is_empty() {
            // Translations join the end of the candidate block, ahead of end-of-candidates.
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

/// A server-reflexive candidate for every foreign address, based on a host candidate of
/// the same family. One per address and port, since every interface shares the socket
/// and would otherwise give the same line.
fn translated_candidates(hosts: &[Vec<&str>], foreign: &[String]) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut emitted: HashSet<(&str, &str)> = HashSet::new();
    let mut foundation = TRANSLATED_FOUNDATION;

    for address in foreign {
        let Some(target) = endpoint::parse(address) else {
            tracing::warn!(
                "advertised address {address} is not an IP literal, so it cannot be announced"
            );
            continue;
        };

        for host in hosts {
            let same_family = matches!(
                (target, endpoint::parse(host[4])),
                (IpAddr::V4(_), Some(IpAddr::V4(_))) | (IpAddr::V6(_), Some(IpAddr::V6(_)))
            );
            if !same_family || !emitted.insert((address.as_str(), host[5])) {
                continue;
            }

            candidates.push(format!(
                "{ATTRIBUTE_PREFIX}{} 1 {} {TRANSLATED_PRIORITY} {} {} typ srflx raddr {} rport {}",
                foundation, host[2], address, host[5], host[4], host[5]
            ));
            foundation += 1;
        }
    }

    candidates
}

fn candidate_type(candidate: &str) -> Option<&str> {
    let parts: Vec<&str> = candidate.split(' ').collect();
    (parts.len() >= 8 && parts[6] == "typ").then(|| parts[7])
}

fn is_host_candidate(candidate: &str) -> bool {
    candidate_type(candidate) == Some("host")
}

/// Whether a STUN or TURN exchange produced the candidate, describing the outside rather
/// than an interface.
fn is_reflexive_or_relayed(candidate: &str) -> bool {
    matches!(candidate_type(candidate), Some("srflx" | "prflx" | "relay"))
}

/// The candidate lines of a description, with their attribute prefix left in place.
fn lines(sdp: &str) -> impl Iterator<Item = &str> {
    sdp.split(['\r', '\n'])
        .filter(|line| line.starts_with(ATTRIBUTE_PREFIX))
}

/// The canonical form of an address, so that the same address written two ways compares
/// equal. Anything that is not an IP literal, such as an mDNS `.local` candidate, is left
/// alone rather than resolved, since a lookup here would block and can only answer for
/// this host.
fn normalized(address: &str) -> String {
    match endpoint::parse(address) {
        Some(address) => host_literal(address),
        None => address.to_string(),
    }
}

fn host_literal(address: IpAddr) -> String {
    address.to_string()
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
    fn the_address_is_the_fifth_token() {
        assert_eq!(
            address("a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host"),
            Some("192.168.1.10")
        );
        assert_eq!(address("a=candidate:1 1 udp"), None);
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

        // Never gathered locally, so every host candidate stays (nothing is "held" to
        // filter down to) and a translation is appended for each host's port.
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
        // 192.168.1.10 is held (advertised and actually gathered), so its translation
        // - not 10.0.0.5's - comes first for the shared IPv4 family.
        let translated = with_advertised_candidates(
            OFFER,
            &["192.168.1.10".to_string(), "203.0.113.1".to_string()],
        );

        let from_held = translated.find("raddr 192.168.1.10").unwrap();
        let from_other = translated.find("raddr 10.0.0.5").unwrap();
        assert!(from_held < from_other, "{translated}");
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

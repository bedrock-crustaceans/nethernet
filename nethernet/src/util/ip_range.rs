//! Sets of addresses written as single hosts or CIDR ranges.

use crate::util::endpoint;
use std::net::IpAddr;

/// A set of addresses written as single hosts or CIDR ranges, such as `10.0.0.0/8` or
/// `2001:db8::/32`. An address with no prefix matches only itself.
#[derive(Debug, Clone, Default)]
pub struct IpRangeSet {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy)]
struct Rule {
    address: IpAddr,
    prefix: u8,
}

impl Rule {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(rule), IpAddr::V4(address)) => {
                matches(&rule.octets(), &address.octets(), self.prefix)
            }
            (IpAddr::V6(rule), IpAddr::V6(address)) => {
                matches(&rule.octets(), &address.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn matches(rule: &[u8], address: &[u8], prefix: u8) -> bool {
    let bytes = prefix as usize / 8;
    if rule[..bytes] != address[..bytes] {
        return false;
    }

    let bits = prefix % 8;
    if bits == 0 {
        return true;
    }

    let mask = 0xffu8 << (8 - bits);
    rule[bytes] & mask == address[bytes] & mask
}

impl IpRangeSet {
    /// Returns a set that matches nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses the entries, skipping any that are not an address or a range.
    pub fn parse<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let rules = entries
            .into_iter()
            .filter_map(|entry| {
                let entry = entry.as_ref().trim();
                match rule(entry) {
                    Some(rule) => Some(rule),
                    None => {
                        tracing::warn!("ignoring malformed address or range: {}", entry);
                        None
                    }
                }
            })
            .collect();

        Self { rules }
    }

    /// Reports whether the set matches nothing.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Reports whether the address falls into one of the ranges.
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = endpoint::normalize(address);
        self.rules.iter().any(|rule| rule.contains(address))
    }
}

fn rule(entry: &str) -> Option<Rule> {
    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (entry, None),
    };

    let address = endpoint::normalize(address.parse::<IpAddr>().ok()?);
    let bits = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    let prefix = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok().filter(|&prefix| prefix <= bits)?,
        None => bits,
    };

    Some(Rule { address, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn a_bare_address_matches_only_itself() {
        let set = IpRangeSet::parse(["203.0.113.7"]);

        assert!(set.contains(ip("203.0.113.7")));
        assert!(!set.contains(ip("203.0.113.8")));
    }

    #[test]
    fn ranges_match_every_address_within_them() {
        let set = IpRangeSet::parse(["10.0.0.0/8", "2001:db8::/32"]);

        assert!(set.contains(ip("10.255.3.1")));
        assert!(!set.contains(ip("11.0.0.1")));
        assert!(set.contains(ip("2001:db8:1::5")));
        assert!(!set.contains(ip("2001:db9::5")));
    }

    #[test]
    fn prefixes_that_do_not_fall_on_a_byte_are_honoured() {
        let set = IpRangeSet::parse(["192.168.4.0/22"]);

        assert!(set.contains(ip("192.168.7.255")));
        assert!(!set.contains(ip("192.168.8.1")));
    }

    #[test]
    fn mapped_addresses_match_their_ipv4_rule() {
        let set = IpRangeSet::parse(["10.0.0.0/8"]);

        assert!(set.contains(ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn malformed_entries_are_skipped() {
        let set = IpRangeSet::parse(["not an address", "10.0.0.0/64", "10.0.0.0/8"]);

        assert!(set.contains(ip("10.0.0.1")));
        assert!(!set.is_empty());
    }
}

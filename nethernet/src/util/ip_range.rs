//! Sets of addresses written as single hosts or CIDR ranges.

use crate::util::endpoint;
use ipnet::{IpNet, Ipv4Net};
use std::net::IpAddr;

/// A set of addresses written as single hosts or CIDR ranges, such as `10.0.0.0/8` or
/// `2001:db8::/32`. An address with no prefix matches only itself.
#[derive(Debug, Clone, Default)]
pub struct IpRangeSet {
    ranges: Vec<IpNet>,
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
        let ranges = entries
            .into_iter()
            .filter_map(|entry| {
                let entry = entry.as_ref().trim();
                let range = range(entry);
                if range.is_none() {
                    tracing::warn!("ignoring malformed address or range: {}", entry);
                }
                range
            })
            .collect();

        Self { ranges }
    }

    /// Reports whether the set matches nothing.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Reports whether the address falls into one of the ranges.
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = endpoint::normalize(address);
        self.ranges.iter().any(|range| range.contains(&address))
    }

    fn into_ipv4_when_mapped(range: IpNet) -> Option<IpNet> {
        const MAPPED_PREFIX: u8 = 96;
        let IpNet::V6(v6) = range else {
            return Some(range);
        };
        let Some(v4) = v6.addr().to_ipv4_mapped() else {
            return Some(range);
        };
        let prefix = v6.prefix_len().checked_sub(MAPPED_PREFIX)?;
        Ipv4Net::new(v4, prefix).ok().map(IpNet::V4)
    }
}

fn range(entry: &str) -> Option<IpNet> {
    match entry.parse::<IpNet>() {
        Ok(range) => IpRangeSet::into_ipv4_when_mapped(range),
        Err(_) => {
            let address = endpoint::normalize(entry.parse::<IpAddr>().ok()?);
            Some(IpNet::from(address))
        }
    }
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

    #[test]
    fn a_zero_prefix_matches_every_address_of_its_family() {
        let set = IpRangeSet::parse(["0.0.0.0/0"]);

        assert!(set.contains(ip("198.51.100.9")));
        assert!(set.contains(ip("::ffff:198.51.100.9")));
        assert!(!set.contains(ip("2001:db8::1")));
    }

    #[test]
    fn a_full_prefix_matches_only_its_host() {
        let set = IpRangeSet::parse(["203.0.113.7/32", "2001:db8::7/128"]);

        assert!(set.contains(ip("203.0.113.7")));
        assert!(!set.contains(ip("203.0.113.6")));
        assert!(set.contains(ip("2001:db8::7")));
        assert!(!set.contains(ip("2001:db8::8")));
    }

    #[test]
    fn entries_are_trimmed() {
        let set = IpRangeSet::parse([
            "  10.0.0.0/8 ",
            "	2001:db8::1
",
        ]);

        assert!(set.contains(ip("10.9.9.9")));
        assert!(set.contains(ip("2001:db8::1")));
    }

    #[test]
    fn a_mapped_bare_entry_matches_the_ipv4_host() {
        let set = IpRangeSet::parse(["::ffff:203.0.113.7"]);

        assert!(set.contains(ip("203.0.113.7")));
        assert!(set.contains(ip("::ffff:203.0.113.7")));
        assert!(!set.contains(ip("203.0.113.8")));
    }

    #[test]
    fn ipv4_ranges_never_match_unmapped_ipv6_addresses() {
        let set = IpRangeSet::parse(["0.0.0.0/0"]);

        assert!(!set.contains(ip("::1")));
    }

    #[test]
    fn a_mapped_range_matches_the_ipv4_addresses_it_covers() {
        let set = IpRangeSet::parse(["::ffff:10.0.0.0/104"]);

        assert!(set.contains(ip("10.1.2.3")));
        assert!(set.contains(ip("::ffff:10.1.2.3")));
        assert!(!set.contains(ip("11.0.0.1")));
    }

    #[test]
    fn a_mapped_host_with_full_prefix_matches_only_itself() {
        let set = IpRangeSet::parse(["::ffff:10.0.0.1/128"]);

        assert!(set.contains(ip("10.0.0.1")));
        assert!(!set.contains(ip("10.0.0.2")));
    }

    #[test]
    fn a_mapped_range_shorter_than_96_bits_is_skipped() {
        let set = IpRangeSet::parse(["::ffff:0:0/64"]);

        assert!(set.is_empty());
    }

    #[test]
    fn a_set_of_only_malformed_entries_is_empty() {
        let set = IpRangeSet::parse(["", "10.0.0.0/", "10.0.0.0/33", "::1/129", "/8"]);

        assert!(set.is_empty());
    }
}

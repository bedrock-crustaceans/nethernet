//! Numeric classification of endpoint addresses.
//!
//! Nothing here resolves a name or probes reachability, so a lookup can never block a
//! state machine or leave the host.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where an address sits, following the IANA special purpose registries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Globally reachable unicast.
    Public,

    /// Reachable from the same network or overlay: RFC 1918, carrier grade NAT, unique local.
    Private,

    /// This host only.
    Loopback,

    /// Special purpose, documentation, or otherwise no use to a peer.
    Unusable,
}

/// Reads an IP literal, never a name.
///
/// The character set also turns away a zone ID, brackets and surrounding space, which
/// the standard library would otherwise accept in some shapes.
pub fn parse(value: &str) -> Option<IpAddr> {
    if value.is_empty()
        || value.len() > 45
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    {
        return None;
    }

    let address = value.parse::<IpAddr>().ok()?;
    Some(normalize(address))
}

/// Unwraps an IPv4 mapped IPv6 address so that two spellings of one address compare equal.
pub fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        address => address,
    }
}

/// Returns the scope of the address.
pub fn scope(address: IpAddr) -> Scope {
    match normalize(address) {
        IpAddr::V4(address) => scope_v4(address),
        IpAddr::V6(address) => scope_v6(address),
    }
}

fn scope_v4(address: Ipv4Addr) -> Scope {
    let [a, b, c, d] = address.octets();

    if a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
    {
        return Scope::Private;
    }
    if a == 127 {
        return Scope::Loopback;
    }
    // 192.0.0.9 and .10 are the PCP and TURN anycast addresses, which a peer can reach
    if a == 0
        || a >= 224
        || (a == 169 && b == 254)
        || (a == 203 && b == 0 && c == 113)
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 192
            && ((b == 88 && c == 99) || (b == 0 && (c == 2 || (c == 0 && d != 9 && d != 10)))))
    {
        return Scope::Unusable;
    }
    Scope::Public
}

fn scope_v6(address: Ipv6Addr) -> Scope {
    let [a, b, ..] = address.segments();

    if a & 0xfe00 == 0xfc00 {
        return Scope::Private;
    }
    if address.is_loopback() {
        return Scope::Loopback;
    }
    // Global unicast is 2000::/3 alone, less 6to4, the protocol block and the two doc ranges
    if a & 0xe000 != 0x2000
        || a == 0x2002
        || (a == 0x2001 && (b < 0x200 || b == 0xdb8))
        || (a == 0x3fff && b < 0x1000)
    {
        return Scope::Unusable;
    }
    Scope::Public
}

/// Reports whether an address is worth publishing.
///
/// A private, carrier grade NAT or unique local address is, since a peer on the same
/// network or overlay reaches it. Loopback only counts when a proxy sits in front.
pub fn advertisable(address: IpAddr, local_development: bool) -> bool {
    match scope(address) {
        Scope::Public | Scope::Private => true,
        Scope::Loopback => local_development,
        Scope::Unusable => false,
    }
}

/// Reports whether a peer on another network could reach the address.
pub fn routable(address: IpAddr) -> bool {
    matches!(scope(address), Scope::Public | Scope::Private)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn names_are_rejected() {
        assert!(parse("example.com").is_none());
        assert!(parse("fe80::1%eth0").is_none());
        assert!(parse("[::1]").is_none());
        assert!(parse(" 127.0.0.1").is_none());
    }

    #[test]
    fn mapped_addresses_are_normalized() {
        assert_eq!(parse("::ffff:192.168.1.1"), Some(ip("192.168.1.1")));
    }

    #[test]
    fn scopes_follow_the_registries() {
        assert_eq!(scope(ip("1.1.1.1")), Scope::Public);
        assert_eq!(scope(ip("10.0.0.1")), Scope::Private);
        assert_eq!(scope(ip("100.64.0.1")), Scope::Private);
        assert_eq!(scope(ip("127.0.0.1")), Scope::Loopback);
        assert_eq!(scope(ip("169.254.1.1")), Scope::Unusable);
        assert_eq!(scope(ip("192.0.2.1")), Scope::Unusable);
        assert_eq!(scope(ip("192.0.0.10")), Scope::Public);
        assert_eq!(scope(ip("2606:4700::1111")), Scope::Public);
        assert_eq!(scope(ip("fd00::1")), Scope::Private);
        assert_eq!(scope(ip("::1")), Scope::Loopback);
        assert_eq!(scope(ip("2001:db8::1")), Scope::Unusable);
        assert_eq!(scope(ip("2002::1")), Scope::Unusable);
    }

    #[test]
    fn loopback_is_only_advertisable_in_local_development() {
        assert!(!advertisable(ip("127.0.0.1"), false));
        assert!(advertisable(ip("127.0.0.1"), true));
        assert!(!advertisable(ip("169.254.1.1"), true));
    }
}

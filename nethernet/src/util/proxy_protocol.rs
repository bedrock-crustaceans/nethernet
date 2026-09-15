//! The PROXY protocol header a reverse proxy puts in front of a connection.
//!
//! Both versions are read: the text form of version 1 and the binary form of version 2.
//! Only the source address is taken, since that is the one thing the transport cannot
//! learn on its own once a proxy sits in front of it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The signature a version 2 header starts with.
const SIGNATURE_V2: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// The prefix a version 1 header starts with.
const SIGNATURE_V1: &[u8] = b"PROXY ";

/// Longest a version 1 header may be, including its terminator.
const MAX_V1: usize = 108;

/// What reading a header off the front of a connection produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// A header was read. The source is [`None`] for a local connection, which a proxy
    /// sends for its own health checks.
    Proxied {
        source: Option<SocketAddr>,
        length: usize,
    },

    /// There is no header, so the bytes belong to the protocol itself.
    Absent,

    /// The header is not complete yet, so more bytes have to be read first.
    Incomplete,
}

/// Reads the header at the front of `buf`.
pub fn read(buf: &[u8]) -> Header {
    if buf.starts_with(&SIGNATURE_V2[..buf.len().min(SIGNATURE_V2.len())]) {
        return match buf.len() >= SIGNATURE_V2.len() {
            true => read_v2(buf),
            false => Header::Incomplete,
        };
    }

    if buf.starts_with(&SIGNATURE_V1[..buf.len().min(SIGNATURE_V1.len())]) {
        return match buf.len() >= SIGNATURE_V1.len() {
            true => read_v1(buf),
            false => Header::Incomplete,
        };
    }

    Header::Absent
}

fn read_v1(buf: &[u8]) -> Header {
    let end = match buf.iter().take(MAX_V1).position(|&b| b == b'\n') {
        Some(end) => end,
        None if buf.len() >= MAX_V1 => return Header::Absent,
        None => return Header::Incomplete,
    };

    let Ok(line) = str::from_utf8(&buf[..end]) else {
        return Header::Absent;
    };
    let length = end + 1;

    let mut parts = line.trim_end_matches('\r').split(' ');
    if parts.next() != Some("PROXY") {
        return Header::Absent;
    }

    match parts.next() {
        Some("TCP4") | Some("TCP6") => {}
        // A proxy sends UNKNOWN for a connection it cannot describe, header and all
        Some("UNKNOWN") => {
            return Header::Proxied {
                source: None,
                length,
            };
        }
        _ => return Header::Absent,
    }

    let (Some(source), Some(_destination), Some(port), Some(_destination_port), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Header::Absent;
    };

    let (Ok(address), Ok(port)) = (source.parse::<IpAddr>(), port.parse::<u16>()) else {
        return Header::Absent;
    };

    Header::Proxied {
        source: Some(SocketAddr::new(address, port)),
        length,
    }
}

fn read_v2(buf: &[u8]) -> Header {
    if buf.len() < 16 {
        return Header::Incomplete;
    }
    if &buf[..12] != SIGNATURE_V2 {
        return Header::Absent;
    }

    // The high nibble is the version, which is the only one this reads
    let version = buf[12] >> 4;
    let command = buf[12] & 0x0f;
    if version != 2 {
        return Header::Absent;
    }

    let family = buf[13] >> 4;
    let address_length = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let length = 16 + address_length;
    if buf.len() < length {
        return Header::Incomplete;
    }

    // A LOCAL command describes the proxy itself, such as a health check
    if command != 1 {
        return Header::Proxied {
            source: None,
            length,
        };
    }

    let addresses = &buf[16..length];
    let source = match family {
        1 if addresses.len() >= 12 => {
            let address = Ipv4Addr::new(addresses[0], addresses[1], addresses[2], addresses[3]);
            let port = u16::from_be_bytes([addresses[8], addresses[9]]);
            Some(SocketAddr::new(address.into(), port))
        }
        2 if addresses.len() >= 36 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addresses[..16]);
            let port = u16::from_be_bytes([addresses[32], addresses[33]]);
            Some(SocketAddr::new(Ipv6Addr::from(octets).into(), port))
        }
        // Anything else is a family the transport has no address for, the header still ran
        _ => None,
    };

    Header::Proxied { source, length }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(family: u8, command: u8, addresses: &[u8]) -> Vec<u8> {
        let mut buf = SIGNATURE_V2.to_vec();
        buf.push(0x20 | command);
        buf.push(family << 4 | 1);
        buf.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
        buf.extend_from_slice(addresses);
        buf
    }

    #[test]
    fn a_plain_connection_carries_no_header() {
        assert_eq!(read(b"POST /v1/join/1234 HTTP/1.1\r\n"), Header::Absent);
    }

    #[test]
    fn a_version_1_header_is_read() {
        let header = b"PROXY TCP4 93.184.216.34 10.0.0.1 51234 443\r\n";

        assert_eq!(
            read(header),
            Header::Proxied {
                source: Some("93.184.216.34:51234".parse().unwrap()),
                length: header.len(),
            }
        );
    }

    #[test]
    fn a_version_1_header_over_ipv6_is_read() {
        let header = b"PROXY TCP6 2001:4860::1 2001:4860::2 51234 443\r\n";

        assert_eq!(
            read(header),
            Header::Proxied {
                source: Some("[2001:4860::1]:51234".parse().unwrap()),
                length: header.len(),
            }
        );
    }

    #[test]
    fn an_unknown_version_1_header_names_no_source() {
        let header = b"PROXY UNKNOWN\r\n";

        assert_eq!(
            read(header),
            Header::Proxied {
                source: None,
                length: header.len(),
            }
        );
    }

    #[test]
    fn a_version_2_header_is_read() {
        let mut addresses = Vec::new();
        addresses.extend_from_slice(&[93, 184, 216, 34]);
        addresses.extend_from_slice(&[10, 0, 0, 1]);
        addresses.extend_from_slice(&51234u16.to_be_bytes());
        addresses.extend_from_slice(&443u16.to_be_bytes());
        let header = v2(1, 1, &addresses);

        assert_eq!(
            read(&header),
            Header::Proxied {
                source: Some("93.184.216.34:51234".parse().unwrap()),
                length: header.len(),
            }
        );
    }

    #[test]
    fn a_local_version_2_header_names_no_source() {
        let header = v2(0, 0, &[]);

        assert_eq!(
            read(&header),
            Header::Proxied {
                source: None,
                length: header.len(),
            }
        );
    }

    #[test]
    fn a_truncated_header_asks_for_more() {
        assert_eq!(read(b"PROXY TCP4 93.184"), Header::Incomplete);
        assert_eq!(read(&SIGNATURE_V2[..8]), Header::Incomplete);
        assert_eq!(read(&v2(1, 1, &[0; 4])[..14]), Header::Incomplete);
    }

    #[test]
    fn a_malformed_header_is_left_to_the_protocol() {
        assert_eq!(read(b"PROXY TCP4 not-an-address 1 2 3\r\n"), Header::Absent);
        assert_eq!(read(b"PROXY WEIRD a b c d\r\n"), Header::Absent);
    }
}

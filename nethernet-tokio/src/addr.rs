//! Address of a peer: network id, connection id and, once known, the media socket address.
use std::fmt;
use std::net::SocketAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addr {
    pub network_id: String,

    /// Zero when the address names a whole network rather than one connection.
    pub connection_id: u64,

    /// Selected media address, filled in once the session knows it.
    pub socket_addr: Option<SocketAddr>,
}

impl Addr {
    pub fn new(network_id: String, connection_id: u64) -> Self {
        Self {
            network_id,
            connection_id,
            socket_addr: None,
        }
    }

    pub fn network(network_id: String) -> Self {
        Self::new(network_id, 0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.network_id)?;
        if self.connection_id != 0 {
            write!(f, " ({})", self.connection_id)?;
        }
        if let Some(addr) = &self.socket_addr {
            write!(f, " ({})", addr)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_address_omits_connection_id() {
        assert_eq!(Addr::network("1234".to_string()).to_string(), "1234");
    }

    #[test]
    fn connection_address_includes_connection_id() {
        assert_eq!(Addr::new("1234".to_string(), 42).to_string(), "1234 (42)");
    }
}

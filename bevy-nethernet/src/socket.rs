use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

// Binding to 0.0.0.0 would advertise that literal address as the session's one ICE
// candidate, so pick a real routable address instead (loopback if none is up).
pub(crate) fn local_bind_addr() -> SocketAddr {
    let probe = || -> std::io::Result<IpAddr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr().map(|addr| addr.ip())
    };

    SocketAddr::new(probe().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
}

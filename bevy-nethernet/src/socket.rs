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

/// Binds the one socket every session of a client or server shares (see
/// [`crate::connection::SessionPool`]).
pub(crate) fn bind_shared_socket() -> std::io::Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind(local_bind_addr())?;
    let addr = socket.local_addr()?;
    Ok((socket, addr))
}

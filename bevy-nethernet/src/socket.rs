use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub(crate) fn local_bind_addr() -> SocketAddr {
    let probe = || -> std::io::Result<IpAddr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr().map(|addr| addr.ip())
    };

    SocketAddr::new(probe().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
}

pub(crate) fn bind_shared_socket() -> std::io::Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind(local_bind_addr())?;
    let addr = socket.local_addr()?;
    Ok((socket, addr))
}

pub(crate) fn bind_discovery_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => bind_dual_stack(addr)?,
        _ => UdpSocket::bind(addr)?,
    };
    socket.set_nonblocking(true)?;
    socket.set_broadcast(true)?;
    Ok(socket)
}

fn bind_dual_stack(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let Ok(socket) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) else {
        return UdpSocket::bind(addr);
    };
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), addr.port()).into())?;
    Ok(socket.into())
}

pub(crate) fn send_discovery(
    socket: &UdpSocket,
    buf: &[u8],
    addr: SocketAddr,
) -> std::io::Result<usize> {
    let addr = match addr {
        SocketAddr::V4(v4) if socket.local_addr()?.is_ipv6() => {
            SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
        }
        _ => addr,
    };
    socket.send_to(buf, addr)
}

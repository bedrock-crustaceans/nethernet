use nethernet::util::endpoint::advertisable;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub(crate) fn local_bind_addr() -> SocketAddr {
    let probe = || -> std::io::Result<IpAddr> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr().map(|addr| addr.ip())
    };

    SocketAddr::new(probe().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0)
}

/// Socket for a server's sessions: bound to every interface, with the addresses to announce for it.
pub(crate) struct ServerMedia {
    pub socket: UdpSocket,
    pub local_addr: SocketAddr,
    pub advertised: Vec<IpAddr>,
}

/// The IPv4 addresses a peer may be able to reach this host on, default route first.
pub(crate) fn advertisable_addresses(primary: IpAddr) -> Vec<IpAddr> {
    let mut found = vec![primary];
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    for interface in interfaces {
        let ip = interface.ip();
        if ip.is_ipv4()
            && !interface.is_loopback()
            && advertisable(ip, false)
            && !found.contains(&ip)
        {
            found.push(ip);
        }
    }
    found
}

pub(crate) fn bind_media() -> std::io::Result<ServerMedia> {
    let primary = local_bind_addr().ip();
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let port = socket.local_addr()?.port();
    Ok(ServerMedia {
        socket,
        local_addr: SocketAddr::new(primary, port),
        advertised: advertisable_addresses(primary),
    })
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

pub(crate) fn recv_discovery(
    socket: &UdpSocket,
    buf: &mut [u8],
    limit: usize,
) -> Vec<(Box<[u8]>, SocketAddr)> {
    let mut received = Vec::new();
    for _ in 0..limit {
        match socket.recv_from(buf) {
            Ok((len, addr)) => received.push((buf[..len].into(), addr)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => tracing::debug!("discovery receive error: {e}"),
        }
    }
    received
}

#[cfg(test)]
mod tests {
    use super::*;
    use nethernet::protocol::constants::MAX_DATAGRAM_SIZE;
    use std::time::{Duration, Instant};

    fn loopback_socket() -> UdpSocket {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    }

    fn recv_within(
        socket: &UdpSocket,
        buf: &mut [u8],
        want: usize,
    ) -> Vec<(Box<[u8]>, SocketAddr)> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut received = Vec::new();
        while received.len() < want && Instant::now() < deadline {
            received.extend(recv_discovery(socket, buf, 16));
            std::thread::sleep(Duration::from_millis(5));
        }
        received
    }

    #[test]
    fn a_3000_byte_signal_is_received_whole() {
        let receiver = loopback_socket();
        let sender = loopback_socket();
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        sender
            .send_to(&[9u8; 3000], receiver.local_addr().unwrap())
            .unwrap();

        let received = recv_within(&receiver, &mut buf, 1);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.len(), 3000);
    }

    #[test]
    fn a_receive_error_does_not_end_the_tick() {
        let receiver = loopback_socket();
        let sender = loopback_socket();
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        sender
            .send_to(&[1u8; 3000], receiver.local_addr().unwrap())
            .unwrap();
        sender
            .send_to(&[2u8; 16], receiver.local_addr().unwrap())
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        let received = recv_discovery(&receiver, &mut buf[..1024], 16);
        assert!(
            received.iter().any(|(data, _)| data.as_ref() == [2u8; 16]),
            "the datagram after a failed receive was left for the next tick"
        );
    }
}

#[cfg(test)]
mod advertise_tests {
    use super::*;

    #[test]
    fn the_default_route_address_leads_and_nothing_repeats() {
        let primary: IpAddr = "192.0.2.10".parse().unwrap();
        let found = advertisable_addresses(primary);
        assert_eq!(found[0], primary);
        let mut sorted = found.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), found.len());
        assert!(found.iter().all(|ip| ip.is_ipv4() && !ip.is_loopback()));
    }

    #[test]
    fn server_media_binds_every_interface_on_the_announced_port() {
        let media = bind_media().unwrap();
        assert!(media.socket.local_addr().unwrap().ip().is_unspecified());
        assert_eq!(
            media.socket.local_addr().unwrap().port(),
            media.local_addr.port()
        );
        assert_eq!(media.advertised[0], media.local_addr.ip());
    }
}

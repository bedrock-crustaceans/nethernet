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

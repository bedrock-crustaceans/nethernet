use bevy_nethernet::prelude::*;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn spin<F: FnMut() -> bool>(deadline: Instant, mut done: F) -> bool {
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn client_connects_to_server_over_http_and_exchanges_data() {
    let mut server = NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |config| {
        config.token_trust = None;
    })
    .unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    let server_url = format!("http://{}", server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    client.connect("5678".to_string(), server_url).unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.is_connected() && server.sessions().next().is_some()
    }));

    client.send(b"hello from client").unwrap();
    let session = server.sessions().next().unwrap().clone();

    assert!(spin(deadline, || {
        server.update();
        client.update();
        server.recv().is_some()
    }));

    server.send(&session, b"hello from server").unwrap();

    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.recv().is_some()
    }));
}

mod raw {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpStream;

    fn bind(conf: impl FnOnce(&mut HttpSignalerConfig)) -> (NetherHttpServer, SocketAddr) {
        let mut server =
            NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), conf).unwrap();
        server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
        let addr = server.local_addr().unwrap();
        (server, addr)
    }

    fn connect(addr: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nonblocking(true).unwrap();
        stream
    }

    struct Reply {
        text: String,
        closed: bool,
    }

    fn collect(server: &mut NetherHttpServer, stream: &mut TcpStream, wait: Duration) -> Reply {
        let deadline = Instant::now() + wait;
        let mut text = String::new();
        let mut closed = false;
        while Instant::now() < deadline && !closed {
            server.update();
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => closed = true,
                Ok(n) => text.push_str(&String::from_utf8_lossy(&chunk[..n])),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => closed = true,
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Reply { text, closed }
    }

    #[test]
    fn request_with_many_headers_is_answered() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        let headers: String = (0..40).map(|i| format!("x-header-{i}: v\r\n")).collect();
        stream
            .write_all(format!("GET /v1/join HTTP/1.1\r\nhost: x\r\n{headers}\r\n").as_bytes())
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 200"), "{}", reply.text);
    }

    #[test]
    fn malformed_request_is_answered_with_400_and_closed() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        stream.write_all(b"NOT HTTP AT ALL\r\n\r\n").unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 400"), "{}", reply.text);
        assert!(reply.closed);
    }

    #[test]
    fn pipelined_requests_are_all_answered() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        let request = "GET /v1/join HTTP/1.1\r\nhost: x\r\n\r\n";
        stream
            .write_all(format!("{request}{request}").as_bytes())
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert_eq!(
            reply.text.matches("HTTP/1.1 200").count(),
            2,
            "{}",
            reply.text
        );
    }

    #[test]
    fn idle_connection_is_closed() {
        let (mut server, addr) = bind(|_| {});
        server.set_idle_timeout(Duration::from_millis(200));
        let mut stream = connect(addr);

        let reply = collect(&mut server, &mut stream, Duration::from_millis(800));

        assert!(reply.closed);
    }

    #[test]
    fn active_connection_outlives_the_idle_timeout() {
        let (mut server, addr) = bind(|_| {});
        server.set_idle_timeout(Duration::from_millis(300));
        let mut stream = connect(addr);
        let request = b"GET /v1/join HTTP/1.1\r\nhost: x\r\n\r\n";

        let mut answered = 0;
        for _ in 0..4 {
            stream.write_all(request).unwrap();
            let reply = collect(&mut server, &mut stream, Duration::from_millis(150));
            answered += reply.text.matches("HTTP/1.1 200").count();
            assert!(!reply.closed);
        }

        assert_eq!(answered, 4);
    }

    #[test]
    fn connection_over_the_per_address_limit_is_closed() {
        let (mut server, addr) = bind(|config| config.max_connections_per_address = 1);
        let mut first = connect(addr);
        collect(&mut server, &mut first, Duration::from_millis(100));
        let mut second = connect(addr);

        let reply = collect(&mut server, &mut second, Duration::from_millis(500));

        assert!(reply.closed);
    }
}

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

#[test]
fn client_connects_with_candidate_inference_disabled() {
    let mut server = NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |config| {
        config.token_trust = None;
    })
    .unwrap();
    server.set_infer_peer_candidates(false);
    let server_url = format!("http://{}", server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    client.connect("5678".to_string(), server_url).unwrap();

    assert!(spin(Instant::now() + Duration::from_secs(10), || {
        server.update();
        client.update();
        client.is_connected() && server.sessions().next().is_some()
    }));
}

#[test]
fn a_connected_session_reports_its_address_and_round_trip_time() {
    let mut server = NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |config| {
        config.token_trust = None;
    })
    .unwrap();
    let server_url = format!("http://{}", server.local_addr().unwrap());
    let mut client = NetherHttpClient::new();
    client.connect("5678".to_string(), server_url).unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.is_connected() && server.sessions().next().is_some()
    }));
    let id = server.sessions().next().unwrap().clone();

    assert!(
        client.remote_addr().is_some(),
        "client has no remote address"
    );
    assert!(
        server.remote_addr(&id).is_some(),
        "server has no remote address"
    );

    client.send(b"ping").unwrap();
    assert!(spin(deadline, || {
        server.update();
        client.update();
        server.recv().is_some()
    }));
    server.send(&id, b"pong").unwrap();
    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.recv().is_some()
    }));

    assert!(
        spin(deadline, || {
            server.update();
            client.update();
            client.rtt().is_some() && server.rtt(&id).is_some()
        }),
        "no round-trip time was reported"
    );
}

fn join_outcome(identity: Option<ServerIdentity>) -> (bool, Vec<NetherHttpClientEvent>) {
    let mut server =
        NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |_| {}).unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    let server_url = format!("http://{}", server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    if let Some(identity) = identity {
        client.set_identity(identity);
    }
    client.connect("5678".to_string(), server_url).unwrap();

    let mut events = Vec::new();
    let joined = spin(Instant::now() + Duration::from_secs(5), || {
        server.update();
        client.update();
        while let Some(event) = client.next_event() {
            events.push(event);
        }
        let failed = events
            .iter()
            .any(|e| matches!(e, NetherHttpClientEvent::ConnectFailed));
        failed || (client.is_connected() && server.sessions().next().is_some())
    });
    (joined && client.is_connected(), events)
}

#[test]
fn a_signed_client_joins_a_validating_server() {
    let identity = ServerIdentity::generate("client", std::time::SystemTime::now()).unwrap();

    let (connected, events) = join_outcome(Some(identity));

    assert!(connected, "signed client did not connect: {events:?}");
}

#[test]
fn a_signed_client_is_visible_to_the_server_as_a_player_on_a_host() {
    let identity = ServerIdentity::generate("client", std::time::SystemTime::now()).unwrap();
    let mut server =
        NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |_| {}).unwrap();
    let address = server.local_addr().unwrap();
    let mut client = NetherHttpClient::new();
    client.set_identity(identity);
    client
        .connect("5678".to_string(), format!("http://{address}"))
        .unwrap();

    assert!(spin(Instant::now() + Duration::from_secs(5), || {
        server.update();
        client.update();
        client.is_connected() && server.sessions().next().is_some()
    }));

    let id = server.sessions().next().unwrap().clone();
    assert!(server.player(&id).is_some(), "no player on the session");
    assert_eq!(server.host(&id), Some(address.to_string().as_str()));
}

#[test]
fn an_unsigned_client_is_refused_by_a_validating_server() {
    let (connected, events) = join_outcome(None);

    assert!(!connected);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, NetherHttpClientEvent::ConnectFailed)),
        "{events:?}"
    );
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

    const PROXY_LINE: &str = "PROXY TCP4 93.184.216.34 127.0.0.1 5000 19132\r\n";
    const JOIN_REQUEST: &str = "GET /v1/join HTTP/1.1\r\nhost: x\r\n\r\n";

    fn trusting_loopback(proxy_protocol: bool) -> impl FnOnce(&mut HttpSignalerConfig) {
        move |config| {
            config.trusted_proxies = nethernet::prelude::IpRangeSet::parse(["127.0.0.1"]);
            config.proxy_protocol = proxy_protocol;
        }
    }

    #[test]
    fn a_trusted_proxy_header_is_read_before_the_request() {
        let (mut server, addr) = bind(trusting_loopback(true));
        let mut stream = connect(addr);
        stream
            .write_all(format!("{PROXY_LINE}{JOIN_REQUEST}").as_bytes())
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 200"), "{}", reply.text);
    }

    #[test]
    fn a_request_without_a_proxy_header_is_answered_from_a_trusted_proxy() {
        let (mut server, addr) = bind(trusting_loopback(true));
        let mut stream = connect(addr);
        stream.write_all(JOIN_REQUEST.as_bytes()).unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 200"), "{}", reply.text);
    }

    #[test]
    fn a_proxy_header_is_a_bad_request_when_the_option_is_off() {
        let (mut server, addr) = bind(trusting_loopback(false));
        let mut stream = connect(addr);
        stream
            .write_all(format!("{PROXY_LINE}{JOIN_REQUEST}").as_bytes())
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 400"), "{}", reply.text);
    }

    #[test]
    fn a_proxy_header_is_a_bad_request_from_an_untrusted_peer() {
        let (mut server, addr) = bind(|config| config.proxy_protocol = true);
        let mut stream = connect(addr);
        stream
            .write_all(format!("{PROXY_LINE}{JOIN_REQUEST}").as_bytes())
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 400"), "{}", reply.text);
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
    fn expect_continue_is_answered_before_the_body_arrives() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        stream
            .write_all(
                b"POST /v1/join HTTP/1.1\r\nhost: x\r\nexpect: 100-continue\r\ncontent-length: 5\r\n\r\n",
            )
            .unwrap();

        let interim = collect(&mut server, &mut stream, Duration::from_millis(300));
        assert!(
            interim.text.starts_with("HTTP/1.1 100 Continue\r\n\r\n"),
            "{}",
            interim.text
        );

        stream.write_all(b"hello").unwrap();
        let last = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(last.text.starts_with("HTTP/1.1 "), "{}", last.text);
        assert!(!last.text.starts_with("HTTP/1.1 100"), "{}", last.text);
    }

    #[test]
    fn chunked_post_does_not_poison_the_next_pipelined_request() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        let post = "POST /v1/join HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let get = "GET /v1/join HTTP/1.1\r\nhost: x\r\n\r\n";
        stream.write_all(format!("{post}{get}").as_bytes()).unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.contains("HTTP/1.1 200"), "{}", reply.text);
    }

    #[test]
    fn oversize_body_is_answered_with_413() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        stream
            .write_all(b"POST /v1/join HTTP/1.1\r\nhost: x\r\ncontent-length: 2000000\r\n\r\n")
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 413"), "{}", reply.text);
    }

    #[test]
    fn a_non_utf8_body_is_answered_with_400() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        stream
            .write_all(b"POST /v1/join HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\n\r\n\xff\xfe")
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 400"), "{}", reply.text);
    }

    #[test]
    fn content_length_with_transfer_encoding_is_answered_with_400() {
        let (mut server, addr) = bind(|_| {});
        let mut stream = connect(addr);
        stream
            .write_all(
                b"GET /v1/join HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\nhello",
            )
            .unwrap();

        let reply = collect(&mut server, &mut stream, Duration::from_millis(500));

        assert!(reply.text.starts_with("HTTP/1.1 400"), "{}", reply.text);
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

#[test]
fn a_join_that_is_never_answered_fails_after_the_negotiation_timeout() {
    let silent_server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_url = format!("http://{}", silent_server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    client.set_timeouts(nethernet::connection::Timeouts {
        negotiation: Duration::from_millis(200),
        ..Default::default()
    });
    client.connect("5678".to_string(), server_url).unwrap();

    let mut failed = false;
    spin(Instant::now() + Duration::from_secs(2), || {
        client.update();
        while let Some(event) = client.next_event() {
            failed |= matches!(event, NetherHttpClientEvent::ConnectFailed);
        }
        failed
    });
    assert!(failed, "no ConnectFailed within the negotiation timeout");
}

fn accepts_before_failure(attempts: u32) -> usize {
    let silent_server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    silent_server.set_nonblocking(true).unwrap();
    let server_url = format!("http://{}", silent_server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    client.set_timeouts(nethernet::connection::Timeouts {
        negotiation: Duration::from_millis(200),
        ..Default::default()
    });
    client.set_attempts(attempts);
    client.connect("5678".to_string(), server_url).unwrap();

    let mut accepted = Vec::new();
    let mut failed = false;
    spin(Instant::now() + Duration::from_secs(3), || {
        client.update();
        while let Ok((stream, _)) = silent_server.accept() {
            accepted.push(stream);
        }
        while let Some(event) = client.next_event() {
            failed |= matches!(event, NetherHttpClientEvent::ConnectFailed);
        }
        failed
    });
    assert!(failed, "no ConnectFailed after the last attempt");
    accepted.len()
}

#[test]
fn a_join_that_times_out_is_retried_on_a_fresh_connection_until_attempts_run_out() {
    assert_eq!(accepts_before_failure(3), 3);
}

#[test]
fn a_single_attempt_joins_exactly_once() {
    assert_eq!(accepts_before_failure(1), 1);
}

#[test]
fn a_query_reads_the_server_data_a_server_advertises() {
    let mut server = NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |config| {
        config.token_trust = None;
    })
    .unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    let server_url = format!("http://{}", server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    client.query_server_data(&server_url).unwrap();

    let mut name = None;
    spin(Instant::now() + Duration::from_secs(5), || {
        server.update();
        client.update();
        while let Some(event) = client.next_event() {
            if let NetherHttpClientEvent::ServerData(data) = event {
                name = Some(data.server_name);
            }
        }
        name.is_some()
    });
    assert_eq!(name.as_deref(), Some("Test Server"));
}

#[test]
fn a_query_that_is_never_answered_fails_after_the_negotiation_timeout() {
    let silent_server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_url = format!("http://{}", silent_server.local_addr().unwrap());

    let mut client = NetherHttpClient::new();
    client.set_timeouts(nethernet::connection::Timeouts {
        negotiation: Duration::from_millis(200),
        ..Default::default()
    });
    client.query_server_data(&server_url).unwrap();

    let mut failed = false;
    spin(Instant::now() + Duration::from_secs(2), || {
        client.update();
        while let Some(event) = client.next_event() {
            failed |= matches!(
                event,
                NetherHttpClientEvent::QueryFailed(QueryError::TimedOut)
            );
        }
        failed
    });
    assert!(failed, "no QueryFailed within the negotiation timeout");
}

#![cfg(feature = "tls")]

use bevy_nethernet::prelude::*;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn self_signed_pair() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let issued =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert.der().clone()], key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(issued.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (Arc::new(server), Arc::new(client))
}

fn server_identity() -> ServerIdentity {
    ServerIdentity::generate("server", std::time::SystemTime::now()).unwrap()
}

fn serve(tls: Arc<ServerConfig>) -> (NetherHttpServer, SocketAddr) {
    serve_with(tls, |_| {})
}

fn serve_with(
    tls: Arc<ServerConfig>,
    conf: impl FnOnce(&mut HttpSignalerConfig),
) -> (NetherHttpServer, SocketAddr) {
    let mut server =
        NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), conf).unwrap();
    server.set_identity(server_identity());
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    server.set_tls(tls);
    let addr = server.local_addr().unwrap();
    (server, addr)
}

fn tls_get(
    server: &mut NetherHttpServer,
    addr: SocketAddr,
    client: Arc<ClientConfig>,
    preamble: &str,
    request: &str,
    answers: usize,
) -> Result<String, String> {
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.write_all(preamble.as_bytes()).unwrap();
    tcp.set_nonblocking(true).unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let connection = ClientConnection::new(client, name).unwrap();
    let mut stream = StreamOwned::new(connection, tcp);

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut sent = false;
    let mut text = String::new();
    while Instant::now() < deadline {
        server.update();
        if !sent {
            match stream.write_all(request.as_bytes()) {
                Ok(()) => sent = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("write: {e}")),
            }
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                text.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if text.matches("HTTP/1.1 200").count() >= answers {
                    return Ok(text);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(format!("read: {e}")),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err(format!("no reply, got {text:?}"))
}

const JOIN_REQUEST: &str = "GET /v1/join HTTP/1.1\r\nhost: localhost\r\n\r\n";

#[test]
fn a_tls_client_gets_the_join_answer_over_a_handshake() {
    let (server_config, client_config) = self_signed_pair();
    let (mut server, addr) = serve(server_config);

    let reply = tls_get(&mut server, addr, client_config, "", JOIN_REQUEST, 1).unwrap();

    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
}

#[test]
fn a_tls_server_answers_one_request_and_closes() {
    let (server_config, client_config) = self_signed_pair();
    let (mut server, addr) = serve(server_config);

    let reply = tls_get(&mut server, addr, client_config, "", JOIN_REQUEST, 1).unwrap();

    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(
        reply.to_ascii_lowercase().contains("connection: close"),
        "{reply}"
    );
}

fn join_server(tls: Arc<ServerConfig>) -> (NetherHttpServer, u16) {
    let mut server = NetherHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |config| {
        config.token_trust = None;
    })
    .unwrap();
    server.set_identity(server_identity());
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    server.set_tls(tls);
    let port = server.local_addr().unwrap().port();
    (server, port)
}

fn spin(deadline: Instant, mut done: impl FnMut() -> bool) -> bool {
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn a_client_joins_over_https_and_exchanges_data() {
    let (server_config, client_config) = self_signed_pair();
    let (mut server, port) = join_server(server_config);

    let mut client = NetherHttpClient::new();
    client.set_tls_config(client_config);
    client
        .connect("5678".to_string(), format!("https://127.0.0.1:{port}"))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.is_connected() && server.sessions().next().is_some()
    }));

    client.send(b"hello over https").unwrap();
    assert!(spin(deadline, || {
        server.update();
        client.update();
        server.recv().is_some()
    }));
}

#[test]
fn an_untrusted_https_certificate_fails_the_join() {
    let (server_config, _) = self_signed_pair();
    let (_, stranger_config) = self_signed_pair();
    let (mut server, port) = join_server(server_config);

    let mut client = NetherHttpClient::new();
    client.set_tls_config(stranger_config);
    client
        .connect("5678".to_string(), format!("https://localhost:{port}"))
        .unwrap();

    let mut failed = false;
    assert!(spin(Instant::now() + Duration::from_secs(10), || {
        server.update();
        client.update();
        while let Some(event) = client.next_event() {
            failed |= matches!(event, NetherHttpClientEvent::ConnectFailed);
        }
        failed
    }));
    assert!(!client.is_connected());
}

#[test]
fn an_unsupported_scheme_is_rejected_before_connecting() {
    let mut client = NetherHttpClient::new();

    let error = client
        .connect("5678".to_string(), "ftp://localhost:1".to_string())
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

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
    let mut server =
        NethernetHttpServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), |config| {
            config.token_trust = None;
        })
        .unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    let server_url = format!("http://{}", server.local_addr().unwrap());

    let mut client = NethernetHttpClient::new();
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

use bevy_nethernet::prelude::*;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const PORT: u16 = 7581;

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
fn client_connects_to_server_and_exchanges_data() {
    let mut server = NetherServer::new(
        1234,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)),
        |config| config.broadcast_interval = Duration::from_millis(50),
    )
    .unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));

    let mut client = NetherClient::new(5678, |config| {
        config.broadcast_address = Some(SocketAddr::from((Ipv4Addr::BROADCAST, PORT)));
        config.broadcast_interval = Duration::from_millis(50);
    })
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.discovered().contains_key(&1234)
    }));

    client.connect(1234).unwrap();

    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.is_connected() && server.sessions().next().is_some()
    }));

    client.send(b"hello from client").unwrap();
    let session = server.sessions().next().unwrap().clone();

    let received = spin(deadline, || {
        server.update();
        client.update();
        server.recv().is_some()
    });
    assert!(received);

    server.send(&session, b"hello from server").unwrap();

    assert!(spin(deadline, || {
        server.update();
        client.update();
        client.recv().is_some()
    }));
}

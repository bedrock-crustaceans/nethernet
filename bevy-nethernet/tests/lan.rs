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

#[test]
fn a_signed_client_connects_to_a_validating_server() {
    const SIGNED_PORT: u16 = 7582;
    let mut server = NetherServer::new(
        1234,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, SIGNED_PORT)),
        |config| config.broadcast_interval = Duration::from_millis(50),
    )
    .unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    server.set_token_trust(Some(nethernet::prelude::TokenTrust::Any));

    let mut client = NetherClient::new(5678, |config| {
        config.broadcast_address = Some(SocketAddr::from((Ipv4Addr::BROADCAST, SIGNED_PORT)));
        config.broadcast_interval = Duration::from_millis(50);
    })
    .unwrap();
    client.set_identity(ServerIdentity::generate("client", std::time::SystemTime::now()).unwrap());

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

    let id = server.sessions().next().unwrap().clone();
    assert!(server.player(&id).is_some(), "no player on the session");
}

#[test]
fn a_connected_session_reports_its_address_and_round_trip_time() {
    const REPORT_PORT: u16 = 7583;
    let mut server = NetherServer::new(
        1234,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, REPORT_PORT)),
        |config| config.broadcast_interval = Duration::from_millis(50),
    )
    .unwrap();
    server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
    let mut client = NetherClient::new(5678, |config| {
        config.broadcast_address = Some(SocketAddr::from((Ipv4Addr::BROADCAST, REPORT_PORT)));
        config.broadcast_interval = Duration::from_millis(50);
    })
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
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

mod admission {
    use super::*;
    use nethernet::connection::{Connection, IceMode};
    use nethernet::prelude::{
        Identity, LanSignaler, LanSignalerInput, LanSignalerOutput, Sans, Signal, SignalErrorCode,
        SignalType, TokenTrust,
    };
    use nethernet::session::Session;
    use std::net::UdpSocket;

    const SERVER_NETWORK: u64 = 1234;
    const PEER_NETWORK: u64 = 5678;
    const CONNECTION_ID: u64 = 42;

    fn loopback_server() -> NetherServer {
        let mut server = NetherServer::new(
            SERVER_NETWORK,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            |_| {},
        )
        .unwrap();
        server.set_server_data(ServerData::new("Test Server".into(), "World".into()));
        server
    }

    struct OfferingPeer {
        socket: UdpSocket,
        signaler: LanSignaler,
    }

    impl OfferingPeer {
        fn aimed_at(server: &mut NetherServer) -> Self {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let config = LanSignalerConfig {
                broadcast_address: Some(server.local_addr().unwrap()),
                ..Default::default()
            };
            let mut peer = Self {
                socket,
                signaler: LanSignaler::new(PEER_NETWORK, config),
            };
            let discovered = spin(Instant::now() + Duration::from_secs(5), || {
                peer.pump(server);
                peer.signaler.address(SERVER_NETWORK).is_some()
            });
            assert!(discovered, "the server never answered discovery");
            peer
        }

        fn pump(&mut self, server: &mut NetherServer) -> Vec<Signal> {
            let _ = self
                .signaler
                .handle(LanSignalerInput::Update(Instant::now()));
            let mut signals = Vec::new();
            while let Some(output) = self.signaler.poll() {
                if let LanSignalerOutput::Datagram(buf, addr) = output {
                    self.socket.send_to(&buf, addr).unwrap();
                }
            }
            server.update();
            let mut buf = [0u8; 2048];
            while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
                let _ = self.signaler.handle(LanSignalerInput::Datagram(
                    buf[..len].into(),
                    from,
                    Instant::now(),
                ));
            }
            while let Some(output) = self.signaler.poll() {
                if let LanSignalerOutput::Signal(signal) = output {
                    signals.push(signal);
                }
            }
            signals
        }

        fn offer(&mut self) {
            let (session, description) =
                Session::new(self.socket.local_addr().unwrap(), true, Instant::now()).unwrap();
            let (_, signals) = Connection::connect(
                session,
                description,
                CONNECTION_ID,
                SERVER_NETWORK.to_string(),
                IceMode::Trickle,
            );
            for signal in signals {
                self.signaler
                    .handle(LanSignalerInput::Signal(signal, Instant::now()))
                    .unwrap();
            }
        }

        fn await_signal(&mut self, server: &mut NetherServer, kind: SignalType) -> Option<Signal> {
            let mut found = None;
            spin(Instant::now() + Duration::from_secs(5), || {
                found = self
                    .pump(server)
                    .into_iter()
                    .find(|signal| signal.signal_type == kind);
                found.is_some()
            });
            found
        }
    }

    #[test]
    fn an_answer_is_signed() {
        let mut server = loopback_server();
        server.set_identity(
            ServerIdentity::generate("server", std::time::SystemTime::now()).unwrap(),
        );
        let mut peer = OfferingPeer::aimed_at(&mut server);

        peer.offer();
        let answer = peer
            .await_signal(&mut server, SignalType::Answer)
            .expect("the offer was never answered");

        assert!(
            Identity::from_sdp(&answer.data).is_ok(),
            "the answer carries no identity"
        );
    }

    #[test]
    fn an_unsigned_offer_is_refused_under_trust() {
        let mut server = loopback_server();
        server.set_token_trust(Some(TokenTrust::Any));
        let mut peer = OfferingPeer::aimed_at(&mut server);

        peer.offer();
        let refusal = peer
            .await_signal(&mut server, SignalType::Error)
            .expect("the offer was not refused");

        assert_eq!(
            refusal.data,
            (SignalErrorCode::NotLoggedIn as u32).to_string()
        );
    }
}

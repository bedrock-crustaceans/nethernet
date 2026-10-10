use nethernet::prelude::TokenTrust;
use nethernet_tokio::signaling::lan::{LanConfig, LanSignaling};
use nethernet_tokio::{AcceptedSession, ConnectionConfig, NetherClient, NetherServer, ServerData};
use std::net::SocketAddr;
use std::time::Duration;

const PORT: u16 = 7571;
const TRUST_PORT: u16 = 7572;

fn config() -> LanConfig {
    config_on(PORT)
}

fn config_on(port: u16) -> LanConfig {
    LanConfig {
        discovery_port: port,
        broadcast_interval: Duration::from_millis(200),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lan_roundtrip() {
    let server_signaling = LanSignaling::with_config(
        1234,
        format!("0.0.0.0:{PORT}").parse::<SocketAddr>().unwrap(),
        config(),
    )
    .await
    .unwrap();
    server_signaling.set_server_data(ServerData::new("test".into(), "world".into()));

    let mut listener = NetherServer::bind(server_signaling).await.unwrap();
    tokio::spawn(async move {
        let AcceptedSession {
            session,
            mut reliable,
            mut unreliable,
        } = listener.accept().await.unwrap();
        let unreliable_session = session.clone();
        tokio::spawn(async move {
            while let Ok(Some(data)) = unreliable.recv().await {
                unreliable_session.send_unreliable(data).await.unwrap();
            }
        });
        while let Ok(Some(data)) = reliable.recv().await {
            session.send(data).await.unwrap();
        }
    });

    let client_signaling = LanSignaling::with_config(5678, "0.0.0.0:0".parse().unwrap(), config())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    let servers = client_signaling.discover().await;
    assert_eq!(servers.len(), 1, "server not discovered");
    assert_eq!(servers[&1234].server_name, "test");

    let mut stream = NetherClient::connect(client_signaling, "1234".to_string())
        .await
        .unwrap();

    stream.send("hello".into()).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"hello");

    stream.send_unreliable("fast".into()).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.recv_unreliable())
        .await
        .expect("unreliable echo timed out")
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"fast");

    assert_eq!(stream.remote_addr().await.network_id, "1234");
    stream.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_trust_rejects_unsigned_lan_offers() {
    let server_signaling = LanSignaling::with_config(
        4321,
        format!("0.0.0.0:{TRUST_PORT}")
            .parse::<SocketAddr>()
            .unwrap(),
        config_on(TRUST_PORT),
    )
    .await
    .unwrap();
    server_signaling.set_server_data(ServerData::new("test".into(), "world".into()));

    let connection_config = ConnectionConfig {
        token_trust: Some(TokenTrust::Any),
        ..Default::default()
    };
    let mut listener = NetherServer::bind_with(server_signaling, connection_config)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let client_signaling =
        LanSignaling::with_config(8765, "0.0.0.0:0".parse().unwrap(), config_on(TRUST_PORT))
            .await
            .unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    let connected = tokio::time::timeout(
        Duration::from_secs(20),
        NetherClient::connect(client_signaling, "4321".to_string()),
    )
    .await
    .expect("negotiation timed out");

    assert!(
        connected.is_err(),
        "an unsigned LAN offer should be refused"
    );
}

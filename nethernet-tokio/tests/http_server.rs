//! End-to-end negotiation over the HTTP endpoint of a server.

use bytes::Bytes;
use nethernet_tokio::signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
use nethernet_tokio::{
    AcceptedSession, ConnectionConfig, NethernetListener, NethernetStream, ServerData,
};
use std::sync::Arc;
use std::time::Duration;

use nethernet::prelude::{HttpSignalerConfig, IpRangeSet, ServerIdentity, TokenTrust};

const NETWORK_ID: &str = "1234";

fn server_config() -> HttpServerConfig {
    HttpServerConfig {
        network_id: NETWORK_ID.to_string(),
        signaler: HttpSignalerConfig {
            answer_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn client_config() -> ConnectionConfig {
    ConnectionConfig {
        identity: Some(Arc::new(
            ServerIdentity::generate("client", std::time::SystemTime::now()).unwrap(),
        )),
        ..Default::default()
    }
}

async fn serve(config: HttpServerConfig) -> (String, NethernetListener<HttpSignalingServer>) {
    let signaling = HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), config)
        .await
        .unwrap();
    signaling.set_server_data(ServerData::new("test".into(), "world".into()));

    let addr = signaling.local_addr();
    let listener = NethernetListener::bind(signaling).await.unwrap();

    (format!("http://{addr}"), listener)
}

#[tokio::test(flavor = "multi_thread")]
async fn offer_is_negotiated_over_the_endpoint() {
    let (url, mut listener) = serve(server_config()).await;

    tokio::spawn(async move {
        let AcceptedSession {
            session,
            mut reliable,
            ..
        } = listener.accept().await.unwrap();
        assert!(session.player().await.is_some());

        while let Ok(Some(data)) = reliable.recv().await {
            session.send(data).await.unwrap();
        }
    });

    let signaling = Arc::new(HttpSignaling::new(NETWORK_ID.to_string()).unwrap());
    let mut stream = tokio::time::timeout(
        Duration::from_secs(20),
        NethernetStream::connect_with(signaling, url, client_config()),
    )
    .await
    .expect("negotiation timed out")
    .expect("failed to connect");

    stream.send(Bytes::from_static(b"hello")).await.unwrap();

    let echoed = tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(echoed.as_deref(), Some(&b"hello"[..]));

    stream.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offer_without_an_identity_is_turned_away() {
    let (url, _listener) = serve(server_config()).await;

    let signaling = Arc::new(HttpSignaling::new(NETWORK_ID.to_string()).unwrap());
    let error = tokio::time::timeout(
        Duration::from_secs(20),
        NethernetStream::connect_with(signaling, url, ConnectionConfig::default()),
    )
    .await
    .expect("negotiation timed out");

    let error = match error {
        Ok(_) => panic!("an offer without an identity should be turned away"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("401"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_status_endpoint_advertises_the_server_data() {
    let (url, _listener) = serve(server_config()).await;

    let body = reqwest::get(format!("{url}/v1/join"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(body.contains("\"name\":\"test\""), "{body}");
    assert!(body.contains("\"level\":\"world\""), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_holding_too_many_connections_is_refused() {
    let config = HttpServerConfig {
        signaler: HttpSignalerConfig {
            max_connections_per_address: 1,
            trusted_proxies: IpRangeSet::empty(),
            token_trust: Some(TokenTrust::Any),
            ..Default::default()
        },
        ..server_config()
    };
    let (url, _listener) = serve(config).await;
    let addr = url.trim_start_matches("http://").to_string();

    let held = tokio::net::TcpStream::connect(&addr).await.unwrap();

    // The second connection is accepted by the kernel and closed without an answer
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let refused = client
        .get(format!("{url}/v1/join"))
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    assert!(refused.is_err(), "{refused:?}");
    drop(held);
}

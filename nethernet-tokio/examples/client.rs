//! NetherNet client example using LAN discovery.
//!
//! This example demonstrates how to create a NetherNet client that:
//! - Discovers servers on LAN via broadcast
//! - Connects via WebRTC
//! - Sends and receives packets

use nethernet_tokio::NethernetStream;
use nethernet_tokio::signaling::lan::LanSignaling;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Level;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    let filter_layer = filter::LevelFilter::from_level(Level::DEBUG);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    // Port 0 so the OS picks a free one, distinct from the server's 7551
    let mut network_id_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut network_id_bytes);
    let network_id = u64::from_le_bytes(network_id_bytes);
    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;

    let signaling = Arc::new(LanSignaling::new(network_id, bind_addr).await?);

    tracing::info!("NetherNet client starting");
    tracing::info!("   Network ID: {}", network_id);
    tracing::info!("   Scanning for servers on LAN...");

    let discovery_timeout_secs = std::env::var("DISCOVERY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3);

    tracing::info!("   Discovery timeout: {}s", discovery_timeout_secs);
    tokio::time::sleep(Duration::from_secs(discovery_timeout_secs)).await;

    let servers = signaling.discover().await;

    if servers.is_empty() {
        tracing::error!("No servers found on LAN!");
        tracing::info!("Make sure a server is running on port 7551");
        return Ok(());
    }

    let (server_network_id, server_data) = servers.iter().next().unwrap();
    tracing::info!("🎯 Found server with network ID: {}", server_network_id);
    tracing::debug!("   Server data: {:?}", server_data);

    tracing::info!("🔗 Connecting to network ID: {}", server_network_id);

    let mut stream =
        NethernetStream::connect(signaling.clone(), server_network_id.to_string()).await?;

    tracing::info!("✅ Connected to {}", stream.remote_addr().await);

    for i in 1..=10 {
        let message = format!("Hello from client, packet #{}", i);

        tracing::debug!("📤 Sending: {}", message);
        stream.write_all(message.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            tracing::warn!("Connection closed by server");
            break;
        }

        let text = String::from_utf8_lossy(&buf[..n]);
        tracing::debug!("📥 Received: {}", text);

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    tracing::info!("📦 Sending large packet (20KB)...");
    let large_data = vec![0xAB; 20_000];
    stream.write_all(&large_data).await?;
    stream.flush().await?;

    let mut response = vec![0u8; 20_000];
    stream.read_exact(&mut response).await?;
    tracing::info!("✅ Large packet echoed back ({} bytes)", response.len());

    tracing::info!("👋 Closing connection...");
    stream.close().await?;
    tracing::info!("✅ Connection closed");

    Ok(())
}

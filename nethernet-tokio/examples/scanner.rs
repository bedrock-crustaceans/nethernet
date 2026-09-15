//! Lists the NetherNet servers advertising themselves on the local network.

use nethernet_tokio::signaling::lan::scan;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let network_id: u64 = rand::random();
    let port = std::env::args()
        .nth(1)
        .and_then(|port| port.parse().ok())
        .unwrap_or(nethernet::protocol::constants::LAN_DISCOVERY_PORT);

    println!("Scanning port {port} for three seconds");
    let found = scan(network_id, port, Duration::from_secs(3)).await?;

    if found.is_empty() {
        println!("No servers answered");
        return Ok(());
    }

    for (network_id, data) in found {
        println!(
            "{network_id}: {} ({}) {}/{} players, game type {}",
            data.server_name,
            data.level_name,
            data.player_count,
            data.max_player_count,
            data.game_type
        );
    }

    Ok(())
}

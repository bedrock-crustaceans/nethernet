use crate::error::Result;
use crate::protocol::packet::discovery::ServerData;
use nethernet::protocol::NetherCodec;

/// Builder for server MOTD/discovery payload (`ServerData`).
///
/// This builder is intended for values passed to `Signaling::set_pong_data`.
#[derive(Debug, Clone)]
pub struct NethernetMotd {
    server_data: ServerData,
}

impl NethernetMotd {
    /// Creates a new MOTD builder with sensible defaults.
    ///
    /// Defaults:
    /// - `game_type = 0` (Survival)
    /// - `player_count = 1`
    /// - `max_player_count = 8`
    /// - `editor_world = false`
    /// - `hardcore = false`
    /// - `transport_layer = 2` (NetherNet)
    /// - `connection_type = 4` (LAN)
    pub fn new(server_name: impl Into<String>, level_name: impl Into<String>) -> Self {
        Self {
            server_data: ServerData::new(server_name.into(), level_name.into()),
        }
    }

    /// Sets the server name.
    pub fn server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_data.server_name = server_name.into();
        self
    }

    /// Sets the level/world name.
    pub fn level_name(mut self, level_name: impl Into<String>) -> Self {
        self.server_data.level_name = level_name.into();
        self
    }

    /// Sets game type.
    pub fn game_type(mut self, game_type: u8) -> Self {
        self.server_data.game_type = game_type;
        self
    }

    /// Sets current player count.
    pub fn player_count(mut self, player_count: i32) -> Self {
        self.server_data.player_count = player_count;
        self
    }

    /// Sets max player count.
    pub fn max_player_count(mut self, max_player_count: i32) -> Self {
        self.server_data.max_player_count = max_player_count;
        self
    }

    /// Sets editor world flag.
    pub fn editor_world(mut self, editor_world: bool) -> Self {
        self.server_data.editor_world = editor_world;
        self
    }

    /// Sets hardcore flag.
    pub fn hardcore(mut self, hardcore: bool) -> Self {
        self.server_data.hardcore = hardcore;
        self
    }

    /// Sets transport layer.
    pub fn transport_layer(mut self, transport_layer: u8) -> Self {
        self.server_data.transport_layer = transport_layer;
        self
    }

    /// Sets connection type.
    pub fn connection_type(mut self, connection_type: u8) -> Self {
        self.server_data.connection_type = connection_type;
        self
    }

    /// Sets the Bedrock protocol version reported by the HTTP `GET /v1/join`
    /// capability check. Has no effect on LAN discovery.
    pub fn protocol_version(mut self, protocol_version: u32) -> Self {
        self.server_data.protocol_version = protocol_version;
        self
    }

    /// Sets the Bedrock game version string (e.g. `"1.26.50"`) reported by the same
    /// endpoint. Has no effect on LAN discovery.
    pub fn game_version(mut self, game_version: impl Into<String>) -> Self {
        self.server_data.game_version = game_version.into();
        self
    }

    /// Builds and returns the underlying `ServerData`.
    pub fn build(self) -> ServerData {
        self.server_data
    }

    /// Encodes the MOTD payload bytes for `Signaling::set_pong_data`.
    pub fn encode(self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.server_data.serialize(&mut buf)?;
        Ok(buf)
    }
}

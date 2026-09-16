//! ServerData binary structure for Minecraft: Bedrock Edition.
//!
//! Encapsulated in ResponsePacket.ApplicationData and sent in response
//! to RequestPacket broadcasted by clients on port 7551.

use crate::error::{ProtocolError, Result};
use crate::protocol::codec::{NetherCodec, read_bytes_u8, write_bytes_u8};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

/// Versions of ServerData the discovery module can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerDataVersion {
    V4,
    V6,
}

impl ServerDataVersion {
    /// Current version written by the discovery module.
    const CURRENT: Self = Self::V6;

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            _ => Err(ProtocolError::Other(format!(
                "unsupported version: got {}, want 4 or 6",
                byte
            ))),
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }
}

/// ServerData defines the binary structure representing worlds in Minecraft: Bedrock Edition.
#[derive(Debug, Clone)]
pub struct ServerData {
    /// Name of the server (typically the player name of the owner)
    pub server_name: String,
    /// Name of the world/level
    pub level_name: String,
    /// Default game mode (0=Survival, 1=Creative, 2=Adventure, 3=Spectator)
    pub game_type: u8,
    /// Current player count (should be at least 1 to appear in server list)
    pub player_count: i32,
    /// Maximum player count allowed
    pub max_player_count: i32,
    /// Whether this is an Editor Mode project
    pub editor_world: bool,
    /// Whether hardcore mode is enabled
    pub hardcore: bool,
    /// Unknown flag introduced in v6 (observed as `1` on vanilla worlds).
    pub flag_a: bool,
    /// Unknown flag introduced in v6 (observed as `1` on vanilla worlds).
    pub flag_b: bool,
    /// Session identifier string introduced in v6; a 16-character lowercase
    /// hex string on vanilla worlds.
    pub session_id: String,
    /// Transport layer (2 = NetherNet)
    pub transport_layer: u8,
    /// Connection type (4 = LAN)
    pub connection_type: u8,
}

impl ServerData {
    /// The server data as the JSON the status endpoint of a server answers with.
    ///
    /// The keys mirror the fields of the binary form, which is what the discovery
    /// response carries on a local network.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ServerName\":{},\"LevelName\":{},\"GameType\":{},\"PlayerCount\":{},\
             \"MaxPlayerCount\":{},\"EditorWorld\":{},\"Hardcore\":{},\"FlagA\":{},\"FlagB\":{},\
             \"SessionID\":{},\"TransportLayer\":{},\"ConnectionType\":{}}}",
            escape(&self.server_name),
            escape(&self.level_name),
            self.game_type,
            self.player_count,
            self.max_player_count,
            self.editor_world,
            self.hardcore,
            self.flag_a,
            self.flag_b,
            escape(&self.session_id),
            self.transport_layer,
            self.connection_type
        )
    }

    /// Constructs a ServerData for the given server and level names using sensible defaults.
    ///
    /// server_name: the server owner or player name.
    /// level_name: the world or level name.
    ///
    /// Defaults:
    /// - game_type = 0 (Survival)
    /// - player_count = 1
    /// - max_player_count = 8
    /// - editor_world = false
    /// - hardcore = false
    /// - flag_a = true
    /// - flag_b = true
    /// - session_id = String
    /// - transport_layer = 2 (NetherNet)
    /// - connection_type = 4 (LAN)
    pub fn new(server_name: String, level_name: String) -> Self {
        Self {
            server_name,
            level_name,
            game_type: 0,
            player_count: 1,
            max_player_count: 8,
            editor_world: false,
            hardcore: false,
            flag_a: true,
            flag_b: true,
            session_id: String::new(),
            transport_layer: 2, // NetherNet
            connection_type: 4, // LAN
        }
    }

    /// Encode the ServerData into the binary format used for discovery ResponsePacket.ApplicationData.
    ///
    /// Returns a vector of bytes on success or a ProtocolError if encoding fails (for example,
    /// if a field value would overflow its encoded form or an I/O write fails).
    ///
    /// Parses a RakNet pong response as sent by Minecraft listeners.
    ///
    /// The pong is a `;` separated list, of which the server name, level name, player
    /// counts and game mode are used. Transport layer and connection type are set to
    /// the values vanilla clients expect for LAN discovery over NetherNet.
    pub fn from_pong_data(data: &[u8]) -> Result<Self> {
        let pong = std::str::from_utf8(data)
            .map_err(|e| ProtocolError::Other(format!("invalid pong data UTF-8: {}", e)))?;
        let parts: Vec<&str> = pong.split(';').collect();
        if parts.len() < 9 {
            return Err(ProtocolError::Other(format!(
                "unexpected pong data format: {} fields, expected at least 9",
                parts.len()
            )));
        }

        Ok(Self {
            server_name: parts[1].to_string(),
            level_name: parts[7].to_string(),
            game_type: game_type(parts[8]),
            player_count: parts[4].parse().unwrap_or(0),
            max_player_count: parts[5].parse().unwrap_or(0),
            editor_world: false,
            hardcore: false,
            flag_a: true,
            flag_b: true,
            session_id: String::new(),
            transport_layer: 2,
            connection_type: 4,
        })
    }

    /// Decodes a complete `ServerData` value from `data`, the way it arrives in
    /// `ResponsePacket::application_data`, returning an error if any bytes remain
    /// unconsumed afterward.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let value = Self::deserialize(&mut cursor)?;

        // Ensure all data was read
        let remaining = data.len() - cursor.position() as usize;
        if remaining != 0 {
            return Err(ProtocolError::Other(format!("unread {} bytes", remaining)));
        }

        Ok(value)
    }
}

impl NetherCodec for ServerData {
    /// Encode the ServerData into the binary format used for discovery ResponsePacket.ApplicationData.
    ///
    /// Returns an error if a field value would overflow its encoded form or an I/O write fails.
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Validate fields that will be shifted to prevent overflow
        if self.game_type >= 128 {
            return Err(ProtocolError::Other(format!(
                "game_type must be less than 128 to avoid overflow, got {}",
                self.game_type
            )));
        }
        if self.transport_layer >= 128 {
            return Err(ProtocolError::Other(format!(
                "transport_layer must be less than 128 to avoid overflow, got {}",
                self.transport_layer
            )));
        }
        if self.connection_type >= 128 {
            return Err(ProtocolError::Other(format!(
                "connection_type must be less than 128 to avoid overflow, got {}",
                self.connection_type
            )));
        }

        // Write version
        writer.write_u8(ServerDataVersion::CURRENT.as_byte())?;

        // Write server name (u8-prefixed string)
        write_bytes_u8(writer, self.server_name.as_bytes())?;

        // Write level name (u8-prefixed string)
        write_bytes_u8(writer, self.level_name.as_bytes())?;

        // Write game type (shifted left by 1)
        writer.write_u8(self.game_type << 1)?;

        // Write player counts (i32 little-endian)
        writer.write_i32::<LittleEndian>(self.player_count)?;
        writer.write_i32::<LittleEndian>(self.max_player_count)?;

        // Write booleans
        writer.write_u8(if self.editor_world { 1 } else { 0 })?;
        writer.write_u8(if self.hardcore { 1 } else { 0 })?;
        writer.write_u8(if self.flag_a { 1 } else { 0 })?;
        writer.write_u8(if self.flag_b { 1 } else { 0 })?;

        // Write session identifier (u8-prefixed string, v6+)
        write_bytes_u8(writer, self.session_id.as_bytes())?;

        // Write transport layer and connection type (both shifted left by 1)
        writer.write_u8(self.transport_layer << 1)?;
        writer.write_u8(self.connection_type << 1)?;

        Ok(())
    }

    /// Decode a ServerData value from its binary representation.
    ///
    /// The function auto-detects versions 4 and 6 from the first byte, reads each
    /// field in the expected order, and validates UTF-8 for string fields. Missing v6
    /// fields are populated with their defaults when decoding v4 data. On success
    /// returns a populated ServerData; on failure returns a ProtocolError describing
    /// the problem. Use [`ServerData::decode`] instead when `reader` should be fully
    /// consumed.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        // Auto-detect the version
        let version = ServerDataVersion::from_byte(reader.read_u8()?)?;

        // Read server name
        let server_name_bytes = read_bytes_u8(reader)?;
        let server_name = String::from_utf8(server_name_bytes)
            .map_err(|e| ProtocolError::Other(format!("invalid server name UTF-8: {}", e)))?;

        // Read level name
        let level_name_bytes = read_bytes_u8(reader)?;
        let level_name = String::from_utf8(level_name_bytes)
            .map_err(|e| ProtocolError::Other(format!("invalid level name UTF-8: {}", e)))?;

        // Read game type (shift right by 1)
        let game_type = reader.read_u8()? >> 1;

        // Read player counts (i32 little-endian)
        let player_count = reader.read_i32::<LittleEndian>()?;
        let max_player_count = reader.read_i32::<LittleEndian>()?;

        // Read booleans
        let editor_world = reader.read_u8()? != 0;
        let hardcore = reader.read_u8()? != 0;

        let (flag_a, flag_b, session_id) = if version == ServerDataVersion::V6 {
            let flag_a = reader.read_u8()? != 0;
            let flag_b = reader.read_u8()? != 0;
            let session_id_bytes = read_bytes_u8(reader)?;
            let session_id = String::from_utf8(session_id_bytes)
                .map_err(|e| ProtocolError::Other(format!("invalid session id UTF-8: {}", e)))?;
            (flag_a, flag_b, session_id)
        } else {
            (true, true, String::new())
        };

        // Read transport layer and connection type (both shift right by 1)
        let transport_layer = reader.read_u8()? >> 1;
        let connection_type = reader.read_u8()? >> 1;

        Ok(Self {
            server_name,
            level_name,
            game_type,
            player_count,
            max_player_count,
            editor_world,
            hardcore,
            flag_a,
            flag_b,
            session_id,
            transport_layer,
            connection_type,
        })
    }

    fn size_hint(&self) -> usize {
        1 // version
            + 1 + self.server_name.len()
            + 1 + self.level_name.len()
            + 1 // game_type
            + 4 + 4 // player counts
            + 4 // booleans
            + 1 + self.session_id.len()
            + 1 + 1 // transport layer, connection type
    }
}

/// Returns the game type for the game mode name of a RakNet pong response.
/// Quotes a string as a JSON value, escaping what the grammar does not allow raw.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn game_type(mode: &str) -> u8 {
    match mode.trim().to_ascii_lowercase().as_str() {
        "creative" => 1,
        "adventure" => 2,
        "spectator" => 6,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_data_roundtrip() {
        let original = ServerData {
            server_name: "Test Server".to_string(),
            level_name: "My World".to_string(),
            game_type: 0,
            player_count: 3,
            max_player_count: 10,
            editor_world: false,
            hardcore: false,
            flag_a: true,
            flag_b: true,
            session_id: "97231188cae9fed6".to_string(),
            transport_layer: 2,
            connection_type: 4,
        };

        let mut encoded = Vec::new();
        original.serialize(&mut encoded).unwrap();
        assert_eq!(encoded[0], ServerDataVersion::CURRENT.as_byte());
        let decoded = ServerData::decode(&encoded).unwrap();

        assert_eq!(original.server_name, decoded.server_name);
        assert_eq!(original.level_name, decoded.level_name);
        assert_eq!(original.game_type, decoded.game_type);
        assert_eq!(original.player_count, decoded.player_count);
        assert_eq!(original.max_player_count, decoded.max_player_count);
        assert_eq!(original.editor_world, decoded.editor_world);
        assert_eq!(original.hardcore, decoded.hardcore);
        assert_eq!(original.flag_a, decoded.flag_a);
        assert_eq!(original.flag_b, decoded.flag_b);
        assert_eq!(original.session_id, decoded.session_id);
        assert_eq!(original.transport_layer, decoded.transport_layer);
        assert_eq!(original.connection_type, decoded.connection_type);
    }

    #[test]
    fn test_v4_is_auto_detected() {
        let mut encoded = Vec::new();
        encoded.write_u8(ServerDataVersion::V4.as_byte()).unwrap();
        write_bytes_u8(&mut encoded, b"Old Server").unwrap();
        write_bytes_u8(&mut encoded, b"Old World").unwrap();
        encoded.write_u8(1 << 1).unwrap();
        encoded.write_i32::<LittleEndian>(2).unwrap();
        encoded.write_i32::<LittleEndian>(20).unwrap();
        encoded.write_u8(1).unwrap();
        encoded.write_u8(0).unwrap();
        encoded.write_u8(2 << 1).unwrap();
        encoded.write_u8(4 << 1).unwrap();

        let decoded = ServerData::decode(&encoded).unwrap();

        assert_eq!(decoded.server_name, "Old Server");
        assert_eq!(decoded.level_name, "Old World");
        assert_eq!(decoded.game_type, 1);
        assert_eq!(decoded.player_count, 2);
        assert_eq!(decoded.max_player_count, 20);
        assert!(decoded.editor_world);
        assert!(!decoded.hardcore);
        assert!(decoded.flag_a);
        assert!(decoded.flag_b);
        assert_eq!(decoded.session_id, "");
        assert_eq!(decoded.transport_layer, 2);
        assert_eq!(decoded.connection_type, 4);
    }

    #[test]
    fn test_from_pong_data() {
        let pong = b"MCPE;Dedicated Server;800;1.21.0;3;10;13253860892328930865;Bedrock level;Creative;1;19132;19133;";
        let data = ServerData::from_pong_data(pong).unwrap();

        assert_eq!(data.server_name, "Dedicated Server");
        assert_eq!(data.level_name, "Bedrock level");
        assert_eq!(data.game_type, 1);
        assert_eq!(data.player_count, 3);
        assert_eq!(data.max_player_count, 10);
        assert_eq!(data.transport_layer, 2);
        assert_eq!(data.connection_type, 4);
    }

    #[test]
    fn test_from_pong_data_rejects_short_input() {
        assert!(ServerData::from_pong_data(b"MCPE;Server").is_err());
    }

    #[test]
    fn test_version_mismatch() {
        let data = vec![5]; // Wrong version
        let result = ServerData::decode(&data);
        assert!(result.is_err());
    }
}

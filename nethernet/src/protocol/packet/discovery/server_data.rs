//! ServerData binary structure for Minecraft: Bedrock Edition.
//!
//! Encapsulated in ResponsePacket.ApplicationData and sent in response
//! to RequestPacket broadcasted by clients on port 7551.

use crate::error::{ProtocolError, Result};
use crate::protocol::codec::{
    NetherCodec, read_bytes_u8, read_bytes_varuint, read_varint32, write_bytes_varuint,
    write_varint32,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

/// Versions of ServerData the discovery module can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerDataVersion {
    V4,
    V6,
    V7,
}

impl ServerDataVersion {
    /// Current version written by the discovery module.
    const CURRENT: Self = Self::V7;

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            7 => Ok(Self::V7),
            _ => Err(ProtocolError::Other(format!(
                "unsupported version: got {}, want 4, 6 or 7",
                byte
            ))),
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
            Self::V7 => 7,
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
    /// Bedrock protocol version. Part of the binary discovery format since
    /// ServerData v7; also used by the HTTP `GET /v1/join` capability check
    /// (guide section 4).
    pub protocol_version: u32,
    /// Bedrock game version string (e.g. `"1.26.50"`). Part of the binary
    /// discovery format since ServerData v7; also used by the same endpoint.
    pub game_version: String,
}

impl ServerData {
    /// The server data as the JSON the `GET /v1/join` capability-check endpoint answers
    /// with (guide section 4), which the client uses to decide whether to attempt a
    /// connection at all and to display server details beforehand.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"name\":{},\"protocol\":{},\"version\":{},\"level\":{},\"players\":{},\
             \"maxPlayers\":{},\"gameType\":{}}}",
            escape(&self.server_name),
            self.protocol_version,
            escape(&self.game_version),
            escape(&self.level_name),
            self.player_count,
            self.max_player_count,
            self.game_type
        )
    }

    /// Constructs a ServerData for the given server and level names using sensible defaults.
    ///
    /// Defaults:
    /// - game_type = 0 (Survival)
    /// - player_count = 1
    /// - max_player_count = 8
    /// - editor_world = false
    /// - hardcore = false
    /// - flag_a = true
    /// - flag_b = true
    /// - session_id = "" (empty)
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
            protocol_version: 0,
            game_version: String::new(),
        }
    }

    /// Parses a RakNet pong response as sent by Minecraft listeners.
    ///
    /// The pong is a `;` separated list, of which the server name, level name, player
    /// counts, game mode, protocol and game version are used. Transport layer and
    /// connection type are set to the values vanilla clients expect for LAN discovery
    /// over NetherNet.
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
            protocol_version: parts[2].parse().unwrap_or(0),
            game_version: parts[3].to_string(),
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

        let remaining = data.len() - cursor.position() as usize;
        if remaining != 0 {
            return Err(ProtocolError::Other(format!("unread {} bytes", remaining)));
        }

        Ok(value)
    }
}

impl NetherCodec for ServerData {
    /// Encode the ServerData into the binary format used for discovery
    /// ResponsePacket.ApplicationData, at the current version (v7).
    ///
    /// Returns an error if a field value would overflow its encoded form or an I/O write fails.
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(ServerDataVersion::CURRENT.as_byte())?;
        write_bytes_varuint(writer, self.server_name.as_bytes())?;
        write_varint32(writer, self.protocol_version as i32)?;
        write_bytes_varuint(writer, self.game_version.as_bytes())?;
        write_bytes_varuint(writer, self.level_name.as_bytes())?;
        write_varint32(writer, self.player_count)?;
        write_varint32(writer, self.max_player_count)?;
        write_varint32(writer, i32::from(self.game_type))?;
        writer.write_u8(if self.editor_world { 1 } else { 0 })?;
        writer.write_u8(if self.hardcore { 1 } else { 0 })?;
        writer.write_u8(if self.flag_a { 1 } else { 0 })?;
        writer.write_u8(if self.flag_b { 1 } else { 0 })?;
        write_bytes_varuint(writer, self.session_id.as_bytes())?;
        write_varint32(writer, i32::from(self.connection_type))?;

        Ok(())
    }

    /// Decode a ServerData value from its binary representation.
    ///
    /// The function auto-detects versions 4, 6 and 7 from the first byte, reads each
    /// field in the expected order, and validates UTF-8 for string fields. Fields a
    /// version does not carry (v6 fields on v4, protocol/version on pre-v7) are
    /// populated with their defaults. On success returns a populated ServerData; on
    /// failure returns a ProtocolError describing the problem. Use
    /// [`ServerData::decode`] instead when `reader` should be fully consumed.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let version = ServerDataVersion::from_byte(reader.read_u8()?)?;

        let read_string = |reader: &mut R, what: &str| -> Result<String> {
            let bytes = read_bytes_u8(reader)?;
            String::from_utf8(bytes)
                .map_err(|e| ProtocolError::Other(format!("invalid {} UTF-8: {}", what, e)))
        };
        let read_var_string = |reader: &mut R, what: &str| -> Result<String> {
            let bytes = read_bytes_varuint(reader)?;
            String::from_utf8(bytes)
                .map_err(|e| ProtocolError::Other(format!("invalid {} UTF-8: {}", what, e)))
        };

        let server_name = read_string(reader, "server name")?;

        // v7 moved protocol/version in front of the level name and switched the
        // numeric fields to varint32.
        let (protocol_version, game_version) = if version == ServerDataVersion::V7 {
            let protocol = read_varint32(reader)?;
            let game_version = read_var_string(reader, "game version")?;
            (protocol as u32, game_version)
        } else {
            (0, String::new())
        };

        let level_name = if version == ServerDataVersion::V7 {
            read_var_string(reader, "level name")?
        } else {
            read_string(reader, "level name")?
        };

        // v7 orders the fields player count, max player count, game type, all
        // varint32; v4/v6 carry the game type (shifted u8) before the i32 counts.
        let (player_count, max_player_count, game_type) = if version == ServerDataVersion::V7 {
            let player_count = read_varint32(reader)?;
            let max_player_count = read_varint32(reader)?;
            let game_type = read_varint32(reader)?;
            (player_count, max_player_count, game_type)
        } else {
            let game_type = i32::from(reader.read_u8()? >> 1);
            let player_count = reader.read_i32::<LittleEndian>()?;
            let max_player_count = reader.read_i32::<LittleEndian>()?;
            (player_count, max_player_count, game_type)
        };
        let game_type = u8::try_from(game_type).map_err(|_| {
            ProtocolError::Other(format!("game type {} does not fit into u8", game_type))
        })?;

        let editor_world = reader.read_u8()? != 0;
        let hardcore = reader.read_u8()? != 0;

        let (flag_a, flag_b, session_id) = if version == ServerDataVersion::V4 {
            (true, true, String::new())
        } else {
            let flag_a = reader.read_u8()? != 0;
            let flag_b = reader.read_u8()? != 0;
            let session_id = if version == ServerDataVersion::V7 {
                read_var_string(reader, "session id")?
            } else {
                read_string(reader, "session id")?
            };
            (flag_a, flag_b, session_id)
        };

        // v7 dropped the transport layer field; discovery only runs over NetherNet.
        let (transport_layer, connection_type) = if version == ServerDataVersion::V7 {
            (2i32, read_varint32(reader)?)
        } else {
            (
                i32::from(reader.read_u8()? >> 1),
                i32::from(reader.read_u8()? >> 1),
            )
        };
        let to_u8 = |value: i32, what: &str| {
            u8::try_from(value).map_err(|_| {
                ProtocolError::Other(format!("{} {} does not fit into u8", what, value))
            })
        };
        let transport_layer = to_u8(transport_layer, "transport layer")?;
        let connection_type = to_u8(connection_type, "connection type")?;

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
            protocol_version,
            game_version,
        })
    }

    fn size_hint(&self) -> usize {
        1 // version
            + 5 + self.server_name.len()
            + 5 // protocol varint32
            + 5 + self.game_version.len()
            + 5 + self.level_name.len()
            + 5 + 5 // player counts
            + 5 // game_type
            + 4 // booleans
            + 5 + self.session_id.len()
            + 5 // connection type
    }
}

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

/// Returns the game type for the game mode name of a RakNet pong response.
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
    use crate::protocol::codec::write_bytes_u8;

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
            protocol_version: 2177,
            game_version: "1.26.50".to_string(),
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
        assert_eq!(original.protocol_version, decoded.protocol_version);
        assert_eq!(original.game_version, decoded.game_version);
    }

    /// Byte-for-byte compatibility with go-nethernet's v7 test vector.
    #[test]
    fn test_v7_matches_go_nethernet_vector() {
        let vector: &[u8] = &[
            0x07, 0x06, b's', b'e', b'r', b'v', b'e', b'r', // server name
            0x8a, 0x22, // protocol: 2181 zigzag varint
            0x07, b'1', b'.', b'2', b'6', b'.', b'5', b'0', // game version
            0x05, b'w', b'o', b'r', b'l', b'd', // level name
            0x02, // player count: 1
            0x10, // max player count: 8
            0x04, // game type: 2 (adventure)
            0x00, // editor world: false
            0x01, // hardcore: true
            0x01, // flag a: true
            0x01, // flag b: true
            0x05, b'n', b'o', b'n', b'c', b'e', // session id
            0x08, // connection type: 4
        ];

        let data = ServerData {
            server_name: "server".to_string(),
            protocol_version: 2181,
            game_version: "1.26.50".to_string(),
            level_name: "world".to_string(),
            game_type: 2,
            player_count: 1,
            max_player_count: 8,
            editor_world: false,
            hardcore: true,
            flag_a: true,
            flag_b: true,
            session_id: "nonce".to_string(),
            transport_layer: 2,
            connection_type: 4,
        };

        let mut encoded = Vec::new();
        data.serialize(&mut encoded).unwrap();
        assert_eq!(encoded, vector);

        let decoded = ServerData::decode(vector).unwrap();
        assert_eq!(decoded.server_name, "server");
        assert_eq!(decoded.protocol_version, 2181);
        assert_eq!(decoded.game_version, "1.26.50");
        assert_eq!(decoded.level_name, "world");
        assert_eq!(decoded.player_count, 1);
        assert_eq!(decoded.max_player_count, 8);
        assert_eq!(decoded.game_type, 2);
        assert!(!decoded.editor_world);
        assert!(decoded.hardcore);
        assert!(decoded.flag_a);
        assert!(decoded.flag_b);
        assert_eq!(decoded.session_id, "nonce");
        assert_eq!(decoded.transport_layer, 2);
        assert_eq!(decoded.connection_type, 4);
    }

    /// A response captured from a vanilla 1.26.51 client hosting a world.
    #[test]
    fn test_v7_real_game_capture() {
        let captured = hex::decode(
            "070a5672646f6e7320303031a22207312e32362e3531\
             0744c3bc6e79616d02100200000101106633633162396234663237626535373908",
        )
        .unwrap();

        let decoded = ServerData::decode(&captured).unwrap();
        assert_eq!(decoded.server_name, "Vrdons 001");
        assert_eq!(decoded.protocol_version, 2193);
        assert_eq!(decoded.game_version, "1.26.51");
        assert_eq!(decoded.level_name, "Dünyam");
        assert_eq!(decoded.player_count, 1);
        assert_eq!(decoded.max_player_count, 8);
        assert_eq!(decoded.game_type, 1);
        assert!(!decoded.editor_world);
        assert!(!decoded.hardcore);
        assert!(decoded.flag_a);
        assert!(decoded.flag_b);
        assert_eq!(decoded.session_id, "f3c1b9b4f27be579");
        assert_eq!(decoded.connection_type, 4);
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

    /// v6 decoding must stay byte-compatible with what pre-1.26 games send.
    #[test]
    fn test_v6_is_auto_detected() {
        let mut encoded = Vec::new();
        encoded.write_u8(ServerDataVersion::V6.as_byte()).unwrap();
        write_bytes_u8(&mut encoded, b"V6 Server").unwrap();
        write_bytes_u8(&mut encoded, b"V6 World").unwrap();
        encoded.write_u8(2 << 1).unwrap(); // game type
        encoded.write_i32::<LittleEndian>(3).unwrap();
        encoded.write_i32::<LittleEndian>(10).unwrap();
        encoded.write_u8(0).unwrap(); // editor world
        encoded.write_u8(1).unwrap(); // hardcore
        encoded.write_u8(1).unwrap(); // flag a
        encoded.write_u8(0).unwrap(); // flag b
        write_bytes_u8(&mut encoded, b"0123456789abcdef").unwrap();
        encoded.write_u8(2 << 1).unwrap(); // transport layer
        encoded.write_u8(4 << 1).unwrap(); // connection type

        let decoded = ServerData::decode(&encoded).unwrap();

        assert_eq!(decoded.server_name, "V6 Server");
        assert_eq!(decoded.level_name, "V6 World");
        assert_eq!(decoded.game_type, 2);
        assert_eq!(decoded.player_count, 3);
        assert_eq!(decoded.max_player_count, 10);
        assert!(!decoded.editor_world);
        assert!(decoded.hardcore);
        assert!(decoded.flag_a);
        assert!(!decoded.flag_b);
        assert_eq!(decoded.session_id, "0123456789abcdef");
        assert_eq!(decoded.transport_layer, 2);
        assert_eq!(decoded.connection_type, 4);
        // v6 has no protocol/version fields
        assert_eq!(decoded.protocol_version, 0);
        assert_eq!(decoded.game_version, "");
    }

    #[test]
    fn test_from_pong_data() {
        let pong = b"MCPE;Dedicated Server;800;1.21.0;3;10;13253860892328930865;Bedrock level;Creative;1;19132;19133;";
        let data = ServerData::from_pong_data(pong).unwrap();

        assert_eq!(data.server_name, "Dedicated Server");
        assert_eq!(data.protocol_version, 800);
        assert_eq!(data.game_version, "1.21.0");
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

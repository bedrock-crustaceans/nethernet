use crate::error::{ProtocolError, Result};
use crate::protocol::codec::{
    NetherCodec, read_bytes_u8, read_bytes_varuint, read_varint32, write_bytes_varuint,
    write_varint32,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerDataVersion {
    V4,
    V5,
    V6,
    V7,
}

impl ServerDataVersion {
    const CURRENT: Self = Self::V7;

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            6 => Ok(Self::V6),
            7 => Ok(Self::V7),
            _ => Err(ProtocolError::Other(format!(
                "unsupported version: got {}",
                byte
            ))),
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
            Self::V7 => 7,
        }
    }
}

/// Server details advertised over discovery or in the HTTP status JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerData {
    pub server_name: String,
    pub level_name: String,
    pub game_type: u8,
    pub player_count: i32,
    pub max_player_count: i32,
    pub editor_world: bool,
    pub hardcore: bool,
    pub flag_a: bool,
    pub flag_b: bool,
    pub session_id: String,
    pub transport_layer: u8,
    pub connection_type: u8,
    pub protocol_version: u32,
    pub game_version: String,
}

impl ServerData {
    /// The HTTP status body, carrying only name, protocol, version, level, players and game type.
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

    pub fn from_json(json: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Status {
            name: String,
            protocol: u32,
            version: String,
            level: String,
            players: i32,
            max_players: i32,
            game_type: u8,
        }

        let status: Status = serde_json::from_str(json)
            .map_err(|e| ProtocolError::Other(format!("invalid server data JSON: {}", e)))?;
        let mut data = Self::new(status.name, status.level);
        data.protocol_version = status.protocol;
        data.game_version = status.version;
        data.player_count = status.players;
        data.max_player_count = status.max_players;
        data.game_type = status.game_type;
        Ok(data)
    }

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
            transport_layer: 2,
            connection_type: 4,
            protocol_version: 0,
            game_version: String::new(),
        }
    }

    /// Parses a semicolon-separated pong string of at least nine fields; unparsable numbers become 0.
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

    /// Reads binary records of versions 4 to 7 and rejects trailing bytes.
    /// Encoding always writes version 7.
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

        let server_name = if version == ServerDataVersion::V4 || version == ServerDataVersion::V6 {
            read_string(reader, "server name")?
        } else {
            read_var_string(reader, "server name")?
        };

        let (protocol_version, game_version) = if version == ServerDataVersion::V7 {
            let protocol = read_varint32(reader)?;
            let game_version = read_var_string(reader, "game version")?;
            (protocol as u32, game_version)
        } else {
            (0, String::new())
        };

        let level_name = if version == ServerDataVersion::V4 || version == ServerDataVersion::V6 {
            read_string(reader, "level name")?
        } else {
            read_var_string(reader, "level name")?
        };

        let (player_count, max_player_count, game_type) = match version {
            ServerDataVersion::V7 => {
                let player_count = read_varint32(reader)?;
                let max_player_count = read_varint32(reader)?;
                let game_type = read_varint32(reader)?;
                (player_count, max_player_count, game_type)
            }
            ServerDataVersion::V5 => {
                let game_type = read_varint32(reader)?;
                let player_count = reader.read_i32::<LittleEndian>()?;
                let max_player_count = reader.read_i32::<LittleEndian>()?;
                (player_count, max_player_count, game_type)
            }
            _ => {
                let game_type = i32::from(reader.read_u8()? >> 1);
                let player_count = reader.read_i32::<LittleEndian>()?;
                let max_player_count = reader.read_i32::<LittleEndian>()?;
                (player_count, max_player_count, game_type)
            }
        };
        let game_type = u8::try_from(game_type).map_err(|_| {
            ProtocolError::Other(format!("game type {} does not fit into u8", game_type))
        })?;

        let editor_world = reader.read_u8()? != 0;
        let hardcore = reader.read_u8()? != 0;

        let (flag_a, flag_b, session_id) = match version {
            ServerDataVersion::V4 => (true, true, String::new()),
            ServerDataVersion::V5 => (
                reader.read_u8()? != 0,
                reader.read_u8()? != 0,
                String::new(),
            ),
            ServerDataVersion::V6 => (
                reader.read_u8()? != 0,
                reader.read_u8()? != 0,
                read_string(reader, "session id")?,
            ),
            ServerDataVersion::V7 => (
                reader.read_u8()? != 0,
                reader.read_u8()? != 0,
                read_var_string(reader, "session id")?,
            ),
        };

        let (transport_layer, connection_type) = match version {
            ServerDataVersion::V7 => (2, read_varint32(reader)?),
            ServerDataVersion::V5 => (read_varint32(reader)?, read_varint32(reader)?),
            _ => (
                i32::from(reader.read_u8()? >> 1),
                i32::from(reader.read_u8()? >> 1),
            ),
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
        1 + 5
            + self.server_name.len()
            + 5
            + 5
            + self.game_version.len()
            + 5
            + self.level_name.len()
            + 5
            + 5
            + 5
            + 4
            + 5
            + self.session_id.len()
            + 5
    }
}

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
    use crate::protocol::codec::write_bytes_u8;

    #[test]
    fn json_status_reads_back_into_the_same_server_data() {
        let mut original = ServerData::new("Name \"Quoted\"".to_string(), "World".to_string());
        original.protocol_version = 2177;
        original.game_version = "1.26.50".to_string();
        original.player_count = 3;
        original.max_player_count = 10;
        original.game_type = 1;

        let read = ServerData::from_json(&original.to_json()).unwrap();

        assert_eq!(read, original);
    }

    #[test]
    fn json_status_missing_a_field_is_rejected() {
        assert!(ServerData::from_json("{\"name\":\"x\"}").is_err());
    }

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

    #[test]
    fn test_v7_matches_go_nethernet_vector() {
        let vector: &[u8] = &[
            0x07, 0x06, b's', b'e', b'r', b'v', b'e', b'r', 0x8a, 0x22, 0x07, b'1', b'.', b'2',
            b'6', b'.', b'5', b'0', 0x05, b'w', b'o', b'r', b'l', b'd', 0x02, 0x10, 0x04, 0x00,
            0x01, 0x01, 0x01, 0x05, b'n', b'o', b'n', b'c', b'e', 0x08,
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

    #[test]
    fn test_v6_is_auto_detected() {
        let mut encoded = Vec::new();
        encoded.write_u8(ServerDataVersion::V6.as_byte()).unwrap();
        write_bytes_u8(&mut encoded, b"V6 Server").unwrap();
        write_bytes_u8(&mut encoded, b"V6 World").unwrap();
        encoded.write_u8(2 << 1).unwrap();
        encoded.write_i32::<LittleEndian>(3).unwrap();
        encoded.write_i32::<LittleEndian>(10).unwrap();
        encoded.write_u8(0).unwrap();
        encoded.write_u8(1).unwrap();
        encoded.write_u8(1).unwrap();
        encoded.write_u8(0).unwrap();
        write_bytes_u8(&mut encoded, b"0123456789abcdef").unwrap();
        encoded.write_u8(2 << 1).unwrap();
        encoded.write_u8(4 << 1).unwrap();

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
        assert_eq!(decoded.protocol_version, 0);
        assert_eq!(decoded.game_version, "");
    }

    #[test]
    fn test_v5_is_auto_detected() {
        let vector: &[u8] = &[
            0x05, 0x06, b's', b'e', b'r', b'v', b'e', b'r', 0x05, b'w', b'o', b'r', b'l', b'd',
            0x04, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x04,
            0x08,
        ];

        let decoded = ServerData::decode(vector).unwrap();
        assert_eq!(decoded.server_name, "server");
        assert_eq!(decoded.level_name, "world");
        assert_eq!(decoded.game_type, 2);
        assert_eq!(decoded.player_count, 1);
        assert_eq!(decoded.max_player_count, 8);
        assert!(!decoded.editor_world);
        assert!(decoded.hardcore);
        assert!(decoded.flag_a);
        assert!(decoded.flag_b);
        assert_eq!(decoded.transport_layer, 2);
        assert_eq!(decoded.connection_type, 4);
        assert_eq!(decoded.session_id, "");
        assert_eq!(decoded.protocol_version, 0);
        assert_eq!(decoded.game_version, "");

        let mut vector = vector.to_vec();
        let flag_b_index = vector.len() - 3;
        vector[flag_b_index] = 0x00;
        let decoded = ServerData::decode(&vector).unwrap();
        assert!(decoded.flag_a);
        assert!(!decoded.flag_b);
    }

    #[test]
    fn test_v5_allows_long_varint_strings() {
        let server_name = "s".repeat(300);
        let level_name = "l".repeat(300);

        let mut encoded = Vec::new();
        encoded.write_u8(ServerDataVersion::V5.as_byte()).unwrap();
        write_bytes_varuint(&mut encoded, server_name.as_bytes()).unwrap();
        write_bytes_varuint(&mut encoded, level_name.as_bytes()).unwrap();
        write_varint32(&mut encoded, 2).unwrap();
        encoded.write_i32::<LittleEndian>(1).unwrap();
        encoded.write_i32::<LittleEndian>(8).unwrap();
        encoded.write_u8(0).unwrap();
        encoded.write_u8(0).unwrap();
        encoded.write_u8(1).unwrap();
        encoded.write_u8(1).unwrap();
        write_varint32(&mut encoded, 2).unwrap();
        write_varint32(&mut encoded, 4).unwrap();

        let decoded = ServerData::decode(&encoded).unwrap();
        assert_eq!(decoded.server_name, server_name);
        assert_eq!(decoded.level_name, level_name);
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
        let data = vec![3];
        let result = ServerData::decode(&data);
        assert!(result.is_err());
    }
}

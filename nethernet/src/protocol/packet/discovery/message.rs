//! Discovery message packet.
//!
//! Sent by both server and client to negotiate a NetherNet connection
//! and exchange ICE candidates.

use crate::error::{ProtocolError, Result};
use crate::protocol::codec::{NetherCodec, read_bytes_u32, write_bytes_u32};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// MessagePacket is used for negotiating WebRTC connections.
/// It contains the recipient network ID and signaling data.
#[derive(Debug, Clone, Default)]
pub struct MessagePacket {
    /// Network ID of the recipient (not the connection ID)
    pub recipient_id: u64,
    /// Signaling data (string form of Signal)
    pub data: String,
}

impl MessagePacket {
    pub fn new(recipient_id: u64, data: String) -> Self {
        Self { recipient_id, data }
    }
}

impl NetherCodec for MessagePacket {
    /// Writes the recipient ID as a little-endian u64, followed by the data as a
    /// 32-bit length-prefixed byte sequence.
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u64::<LittleEndian>(self.recipient_id)?;
        write_bytes_u32(writer, self.data.as_bytes())?;
        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let recipient_id = reader.read_u64::<LittleEndian>()?;
        let data_bytes = read_bytes_u32(reader)?;
        let data = String::from_utf8(data_bytes)
            .map_err(|e| ProtocolError::Other(format!("invalid UTF-8: {}", e)))?;
        Ok(Self { recipient_id, data })
    }

    fn size_hint(&self) -> usize {
        std::mem::size_of::<u64>() + std::mem::size_of::<u32>() + self.data.len()
    }
}

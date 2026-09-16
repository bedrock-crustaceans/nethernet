//! Discovery response packet.
//!
//! Sent by servers in response to a RequestPacket from clients
//! to advertise the world/server information.
use crate::error::{ProtocolError, Result};
use crate::protocol::codec::{NetherCodec, read_bytes_u32};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::{Read, Write};

/// ResponsePacket is sent by servers to respond to discovery requests.
/// It contains hex-encoded ServerData payload.
#[derive(Debug, Clone, Default)]
pub struct ResponsePacket {
    /// Application-specific data (typically ServerData in Minecraft: Bedrock Edition)
    pub application_data: Vec<u8>,
}

impl ResponsePacket {
    /// Create a ResponsePacket containing the provided application data.
    pub fn new(application_data: Vec<u8>) -> Self {
        Self { application_data }
    }
}

impl NetherCodec for ResponsePacket {
    /// Writes the packet's application_data as a hex-encoded byte sequence (prefixed with a 32-bit length) to `writer`.
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Hex-encoded in chunks rather than all at once, to avoid a large allocation
        let len = self.application_data.len();
        let hex_len = len * 2;

        writer.write_u32::<LittleEndian>(hex_len as u32)?;

        let mut buf = [0u8; 2048];
        for chunk in self.application_data.chunks(512) {
            let encoded_len = chunk.len() * 2;
            hex::encode_to_slice(chunk, &mut buf[..encoded_len])
                .map_err(|e| ProtocolError::Other(format!("hex encode error: {}", e)))?;
            writer.write_all(&buf[..encoded_len])?;
        }
        Ok(())
    }

    /// Reads hex-encoded application data from `reader` and decodes it into `application_data`.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let hex_data = read_bytes_u32(reader)?;
        let application_data = hex::decode(&hex_data)
            .map_err(|e| ProtocolError::Other(format!("hex decode error: {}", e)))?;

        Ok(Self { application_data })
    }

    fn size_hint(&self) -> usize {
        std::mem::size_of::<u32>() + self.application_data.len() * 2
    }
}

use super::crypto::{compute_checksum, decrypt, encrypt, verify_checksum};
use super::{MessagePacket, RequestPacket, ResponsePacket};
use crate::error::{ProtocolError, Result};
use crate::protocol::codec::NetherCodec;
use crate::protocol::constants::{ID_MESSAGE_PACKET, ID_REQUEST_PACKET, ID_RESPONSE_PACKET};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

pub enum Packets {
    Request(RequestPacket),
    Response(ResponsePacket),
    Message(MessagePacket),
}

impl Packets {
    pub fn id(&self) -> u16 {
        match self {
            Packets::Request(_) => ID_REQUEST_PACKET,
            Packets::Response(_) => ID_RESPONSE_PACKET,
            Packets::Message(_) => ID_MESSAGE_PACKET,
        }
    }

    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Packets::Request(packet) => packet.serialize(writer),
            Packets::Response(packet) => packet.serialize(writer),
            Packets::Message(packet) => packet.serialize(writer),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub packet_id: u16,
    pub sender_id: u64,
}

impl NetherCodec for Header {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<LittleEndian>(self.packet_id)?;
        writer.write_u64::<LittleEndian>(self.sender_id)?;
        writer.write_all(&[0u8; 8])?;
        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let packet_id = reader.read_u16::<LittleEndian>()?;
        let sender_id = reader.read_u64::<LittleEndian>()?;

        let mut padding = [0u8; 8];
        reader.read_exact(&mut padding)?;

        Ok(Self {
            packet_id,
            sender_id,
        })
    }

    fn size_hint(&self) -> usize {
        std::mem::size_of::<u16>() + std::mem::size_of::<u64>() + 8
    }
}

pub fn encode(packet: &Packets, sender_id: u64) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(2 + 18 + 64 + 16);

    payload.extend_from_slice(&[0u8; 2]);

    let header = Header {
        packet_id: packet.id(),
        sender_id,
    };
    header.serialize(&mut payload)?;
    packet.serialize(&mut payload)?;

    let data_len = payload.len() - 2;
    if data_len > u16::MAX as usize {
        return Err(ProtocolError::MessageTooLarge(data_len));
    }
    payload[..2].copy_from_slice(&(data_len as u16).to_le_bytes());

    let checksum = compute_checksum(&payload);
    encrypt(&mut payload)?;

    let mut buf = Vec::with_capacity(32 + payload.len());
    buf.extend_from_slice(&checksum);
    buf.extend_from_slice(&payload);

    Ok(buf)
}

pub fn decode(data: &[u8]) -> Result<(Packets, u64)> {
    if data.len() < 32 {
        return Err(ProtocolError::Other("packet too short".to_string()));
    }

    let checksum: [u8; 32] = data[..32].try_into().unwrap();

    let mut payload = data[32..].to_vec();
    decrypt(&mut payload)?;

    if !verify_checksum(&payload, &checksum) {
        return Err(ProtocolError::Other("checksum mismatch".to_string()));
    }

    let mut cursor = Cursor::new(payload);
    let _length = cursor.read_u16::<LittleEndian>()?;
    let header = Header::deserialize(&mut cursor)?;

    let packet = match header.packet_id {
        ID_REQUEST_PACKET => Packets::Request(RequestPacket::deserialize(&mut cursor)?),
        ID_RESPONSE_PACKET => Packets::Response(ResponsePacket::deserialize(&mut cursor)?),
        ID_MESSAGE_PACKET => Packets::Message(MessagePacket::deserialize(&mut cursor)?),
        id => {
            return Err(ProtocolError::Other(format!("unknown packet ID: {}", id)));
        }
    };

    let cursor_position = cursor.position() as usize;
    let payload_len = cursor.get_ref().len();
    if cursor_position < payload_len {
        let remaining = payload_len - cursor_position;
        return Err(ProtocolError::Other(format!(
            "trailing data in packet: {} remaining bytes out of {} total payload bytes",
            remaining, payload_len
        )));
    }

    Ok((packet, header.sender_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header {
            packet_id: 0x01,
            sender_id: 0x1234567890abcdef,
        };

        let mut buf = Vec::new();
        header.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = Header::deserialize(&mut cursor).unwrap();

        assert_eq!(header.packet_id, decoded.packet_id);
        assert_eq!(header.sender_id, decoded.sender_id);
    }
}

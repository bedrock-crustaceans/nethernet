//! Little-endian codec trait and length-prefixed primitives for discovery packets.
use crate::error::{ProtocolError, Result};
use crate::protocol::constants::MAX_BYTES;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

pub trait NetherCodec: Sized {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()>;

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self>;

    fn size_hint(&self) -> usize;
}

pub fn read_bytes_u8<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u8()? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Fails when the data is longer than 255 bytes.
pub fn write_bytes_u8<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = u8::try_from(data.len()).map_err(|_| {
        ProtocolError::Other(format!(
            "data length {} exceeds the 255-byte maximum for a u8-prefixed field",
            data.len()
        ))
    })?;
    writer.write_u8(len)?;
    writer.write_all(data)?;
    Ok(())
}

/// Refuses a length prefix above `MAX_BYTES`.
pub fn read_bytes_u32<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u32::<LittleEndian>()? as usize;
    if len > MAX_BYTES {
        return Err(ProtocolError::Other(format!(
            "byte array length {} exceeds maximum allowed {}",
            len, MAX_BYTES
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_bytes_u32<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_BYTES {
        return Err(ProtocolError::Other(format!(
            "data length {} exceeds maximum allowed {}",
            data.len(),
            MAX_BYTES
        )));
    }
    writer.write_u32::<LittleEndian>(data.len() as u32)?;
    writer.write_all(data)?;
    Ok(())
}

/// Reads a LEB128 varint of at most five bytes.
pub fn read_varuint32<R: Read>(reader: &mut R) -> Result<u32> {
    let mut value: u32 = 0;
    for shift in (0..35).step_by(7) {
        let byte = reader.read_u8()?;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProtocolError::Other(
        "varuint32 did not terminate after 5 bytes".to_string(),
    ))
}

pub fn write_varuint32<W: Write>(writer: &mut W, mut value: u32) -> Result<()> {
    while value >= 0x80 {
        writer.write_u8((value as u8) | 0x80)?;
        value >>= 7;
    }
    writer.write_u8(value as u8)?;
    Ok(())
}

/// Reads a zigzag-encoded varint.
pub fn read_varint32<R: Read>(reader: &mut R) -> Result<i32> {
    let raw = read_varuint32(reader)?;
    Ok(((raw >> 1) as i32) ^ -((raw & 1) as i32))
}

pub fn write_varint32<W: Write>(writer: &mut W, value: i32) -> Result<()> {
    write_varuint32(writer, ((value << 1) ^ (value >> 31)) as u32)
}

/// The varuint length prefix is not capped, unlike the u32 reader.
pub fn read_bytes_varuint<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = read_varuint32(reader)? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_bytes_varuint<W: Write>(writer: &mut W, data: &[u8]) -> Result<()> {
    write_varuint32(writer, data.len() as u32)?;
    writer.write_all(data)?;
    Ok(())
}

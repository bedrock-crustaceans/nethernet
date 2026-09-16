//! A codec trait for NetherNet's own wire-format types, in the style of the sibling
//! raknet crate's `RakCodec`.
//!
//! External wire formats NetherNet only carries (SDP, ICE candidates, DCEP) keep the
//! `Marshal`/`Unmarshal` naming of the crates that define them; this trait is for the
//! discovery packets and other types NetherNet defines itself.

use crate::error::{ProtocolError, Result};
use crate::protocol::constants::MAX_BYTES;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// Types that can be losslessly serialized to and deserialized from the NetherNet wire
/// format.
pub trait NetherCodec: Sized {
    /// Writes the encoded form of `self` to `writer`.
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()>;

    /// Reads and decodes a value from `reader`.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self>;

    /// A best-effort estimate of the encoded size, used to pre-size output buffers.
    fn size_hint(&self) -> usize;
}

/// Reads a `u8`-length-prefixed byte array.
pub fn read_bytes_u8<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u8()? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Writes `data` prefixed by its length as a single `u8`, erroring if it does not fit.
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

/// Reads a little-endian `u32`-length-prefixed byte array, rejecting lengths over
/// [`MAX_BYTES`] before allocating.
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

/// Writes `data` prefixed by its length as a little-endian `u32`, rejecting data over
/// [`MAX_BYTES`].
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

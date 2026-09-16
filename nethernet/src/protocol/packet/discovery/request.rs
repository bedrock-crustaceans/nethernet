//! Discovery request packet.
//!
//! Sent by clients to discover servers on the same network using the
//! broadcast address on port 7551.

use crate::error::Result;
use crate::protocol::codec::NetherCodec;
use std::io::{Read, Write};

/// RequestPacket is sent by clients to discover servers on LAN.
/// It does not contain any additional data beyond the header.
#[derive(Debug, Clone, Default)]
pub struct RequestPacket;

impl NetherCodec for RequestPacket {
    fn serialize<W: Write>(&self, _writer: &mut W) -> Result<()> {
        // No data to write
        Ok(())
    }

    fn deserialize<R: Read>(_reader: &mut R) -> Result<Self> {
        // No data to read
        Ok(RequestPacket)
    }

    fn size_hint(&self) -> usize {
        0
    }
}

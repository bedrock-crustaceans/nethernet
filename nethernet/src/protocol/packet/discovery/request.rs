use crate::error::Result;
use crate::protocol::codec::NetherCodec;
use std::io::{Read, Write};

#[derive(Debug, Clone, Default)]
pub struct RequestPacket;

impl NetherCodec for RequestPacket {
    fn serialize<W: Write>(&self, _writer: &mut W) -> Result<()> {
        Ok(())
    }

    fn deserialize<R: Read>(_reader: &mut R) -> Result<Self> {
        Ok(RequestPacket)
    }

    fn size_hint(&self) -> usize {
        0
    }
}

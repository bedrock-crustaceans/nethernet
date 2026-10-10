use crate::error::ProtocolError;
use rtc::datachannel::message::Message;
use rtc::datachannel::message::message_channel_ack::DataChannelAck;
use rtc::datachannel::message::message_channel_open::{
    CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
};
use rtc::sctp::PayloadProtocolIdentifier;
use rtc::shared::marshal::{Marshal, Unmarshal};

pub const RELIABLE_CHANNEL_LABEL: &str = "ReliableDataChannel";
pub const UNRELIABLE_CHANNEL_LABEL: &str = "UnreliableDataChannel";

pub const PPI_DCEP: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Dcep;

pub fn reliable_open() -> DataChannelOpen {
    DataChannelOpen {
        channel_type: ChannelType::Reliable,
        priority: CHANNEL_PRIORITY_NORMAL,
        reliability_parameter: 0,
        label: RELIABLE_CHANNEL_LABEL.as_bytes().to_vec(),
        protocol: Vec::new(),
    }
}

pub fn unreliable_open() -> DataChannelOpen {
    DataChannelOpen {
        channel_type: ChannelType::PartialReliableRexmitUnordered,
        priority: CHANNEL_PRIORITY_NORMAL,
        reliability_parameter: 0,
        label: UNRELIABLE_CHANNEL_LABEL.as_bytes().to_vec(),
        protocol: Vec::new(),
    }
}

pub fn encode_open(open: DataChannelOpen) -> Result<Vec<u8>, ProtocolError> {
    Message::DataChannelOpen(open)
        .marshal()
        .map(|b| b.to_vec())
        .map_err(|e| ProtocolError::Other(format!("encode DATA_CHANNEL_OPEN: {e}")))
}

pub fn encode_ack() -> Result<Vec<u8>, ProtocolError> {
    Message::DataChannelAck(DataChannelAck)
        .marshal()
        .map(|b| b.to_vec())
        .map_err(|e| ProtocolError::Other(format!("encode DATA_CHANNEL_ACK: {e}")))
}

pub fn decode(mut data: &[u8]) -> Result<Message, ProtocolError> {
    Message::unmarshal(&mut data).map_err(|e| ProtocolError::Other(format!("decode DCEP: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliable_open_roundtrip() {
        let encoded = encode_open(reliable_open()).unwrap();
        let Message::DataChannelOpen(open) = decode(&encoded).unwrap() else {
            panic!("expected DataChannelOpen");
        };
        assert_eq!(open.channel_type, ChannelType::Reliable);
        assert_eq!(open.label, RELIABLE_CHANNEL_LABEL.as_bytes());
    }

    #[test]
    fn unreliable_open_roundtrip() {
        let encoded = encode_open(unreliable_open()).unwrap();
        let Message::DataChannelOpen(open) = decode(&encoded).unwrap() else {
            panic!("expected DataChannelOpen");
        };
        assert_eq!(
            open.channel_type,
            ChannelType::PartialReliableRexmitUnordered
        );
        assert_eq!(open.reliability_parameter, 0);
        assert_eq!(open.label, UNRELIABLE_CHANNEL_LABEL.as_bytes());
    }

    #[test]
    fn ack_roundtrip() {
        let encoded = encode_ack().unwrap();
        assert!(matches!(
            decode(&encoded).unwrap(),
            Message::DataChannelAck(_)
        ));
    }
}

use crate::error::{ProtocolError, Result};
use crate::protocol::constants::MAX_MESSAGE_SIZE;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Message segment
/// First byte contains segment count, remainder contains data
#[derive(Debug, Clone)]
pub struct MessageSegment {
    /// Remaining segment count (0 = last segment)
    pub remaining_segments: u8,
    /// Segment data
    pub data: Bytes,
}

impl MessageSegment {
    /// Creates a [`MessageSegment`] with the given remaining segment count and payload.
    pub fn new(remaining_segments: u8, data: Bytes) -> Self {
        Self {
            remaining_segments,
            data,
        }
    }

    /// Serializes the segment: the remaining-segment count followed by the payload.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + self.data.len());
        buf.put_u8(self.remaining_segments);
        buf.extend_from_slice(&self.data);
        buf.freeze()
    }

    /// Decode a MessageSegment from bytes.
    ///
    /// This is zero-copy as the input `Bytes` is used for the payload.
    /// Minimum length is 2 bytes (1 for segment count + at least 1 for data) to match go-nethernet.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < 2 {
            return Err(ProtocolError::MessageParse(format!(
                "Message too short, expected at least 2 bytes, got {}",
                data.len()
            )));
        }

        let remaining_segments = data[0];
        data.advance(1);
        Ok(Self {
            remaining_segments,
            data,
        })
    }
}

/// Complete message - data assembled from segments
#[derive(Debug, Clone)]
pub struct Message {
    /// Expected segment count
    expected_segments: u8,
    /// Assembled data
    data: BytesMut,
}

impl Message {
    /// Creates a new, empty Message ready to receive segments.
    pub fn new() -> Self {
        Self {
            expected_segments: 0,
            data: BytesMut::new(),
        }
    }

    /// Adds a segment, returning the complete message once assembly finishes.
    ///
    /// An out-of-order segment clears the accumulator and returns a `MessageParse` error.
    pub fn add_segment(&mut self, segment: MessageSegment) -> Result<Option<Bytes>> {
        if self.expected_segments == 0 && segment.remaining_segments > 0 {
            self.expected_segments =
                segment.remaining_segments.checked_add(1).ok_or_else(|| {
                    ProtocolError::MessageParse("segment count out of range".to_string())
                })?;
            let estimated = self.expected_segments as usize * MAX_MESSAGE_SIZE;
            self.data.reserve(estimated);
        }

        if self.expected_segments > 0 {
            let expected_remaining = self.expected_segments - 1;
            if expected_remaining != segment.remaining_segments {
                // Reset so the instance is safe to reuse after this error
                self.data.clear();
                self.expected_segments = 0;
                return Err(ProtocolError::MessageParse(format!(
                    "Invalid segment sequence: expected {}, got {}",
                    expected_remaining, segment.remaining_segments
                )));
            }
            self.expected_segments -= 1;
        }

        self.data.put(segment.data);

        if segment.remaining_segments == 0 {
            let data = self.data.split().freeze();
            self.expected_segments = 0;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Splits a byte buffer into protocol-sized message segments.
    ///
    /// For inputs shorter than or equal to MAX_MESSAGE_SIZE this returns a single
    /// segment with `remaining_segments` equal to 0. For longer inputs the data
    /// is chunked into segments of at most MAX_MESSAGE_SIZE bytes; the first
    /// returned segment has `remaining_segments = segment_count - 1` and the last
    /// has `remaining_segments = 0`.
    #[inline(always)]
    pub fn split_into_segments(data: Bytes) -> Result<Vec<MessageSegment>> {
        let len = data.len();

        if len <= MAX_MESSAGE_SIZE {
            return Ok(vec![MessageSegment::new(0, data)]);
        }

        let segment_count = len.div_ceil(MAX_MESSAGE_SIZE);

        if segment_count > 255 {
            return Err(ProtocolError::MessageTooLarge(len));
        }

        let mut segments = Vec::with_capacity(segment_count);

        let mut remaining = data;
        let mut left = segment_count as u8;

        while remaining.len() > MAX_MESSAGE_SIZE {
            left -= 1;

            let chunk = remaining.split_to(MAX_MESSAGE_SIZE);

            segments.push(MessageSegment::new(left, chunk));
        }

        if !remaining.is_empty() {
            left -= 1;
            segments.push(MessageSegment::new(left, remaining));
        }

        debug_assert_eq!(left, 0);

        Ok(segments)
    }

    /// Encodes a single-fragment message for the unreliable channel, which never
    /// fragments (per the NetherNet HTTP signaling guide, section 6.1) and rejects
    /// anything too large instead.
    pub fn encode_unreliable(data: Bytes) -> Result<Bytes> {
        if data.len() > MAX_MESSAGE_SIZE.saturating_sub(1) {
            return Err(ProtocolError::MessageTooLarge(data.len()));
        }
        Ok(MessageSegment::new(0, data).encode())
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_segment() {
        let data = Bytes::from("Hello, World!");
        let segments = Message::split_into_segments(data.clone()).unwrap();

        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].remaining_segments, 0);
        assert_eq!(segments[0].data, data);
    }

    #[test]
    fn test_multiple_segments() {
        let data = Bytes::from(vec![0u8; MAX_MESSAGE_SIZE * 2 + 100]);
        let segments = Message::split_into_segments(data.clone()).unwrap();

        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].remaining_segments, 2);
        assert_eq!(segments[1].remaining_segments, 1);
        assert_eq!(segments[2].remaining_segments, 0);
    }

    #[test]
    fn test_reassembly() {
        let original_data = Bytes::from(vec![1u8; MAX_MESSAGE_SIZE * 2 + 100]);
        let segments = Message::split_into_segments(original_data.clone()).unwrap();

        let mut message = Message::new();
        for (i, segment) in segments.iter().enumerate() {
            let result = message.add_segment(segment.clone()).unwrap();
            if i < segments.len() - 1 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
                assert_eq!(result.unwrap(), original_data);
            }
        }
    }

    #[test]
    fn test_out_of_order_segments_error() {
        let data = Bytes::from(vec![42u8; MAX_MESSAGE_SIZE * 2 + 100]);
        let segments = Message::split_into_segments(data.clone()).unwrap();
        assert!(segments.len() >= 3);

        let mut message = Message::new();

        // Adding the middle segment first is what sets expected_segments, so it succeeds
        let result = message.add_segment(segments[1].clone());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Segment 0 is out of sequence now that segment 1 already set the expectation
        let result = message.add_segment(segments[0].clone());
        assert!(result.is_err());

        if let Err(ProtocolError::MessageParse(msg)) = result {
            assert!(msg.contains("Invalid segment sequence"));
        } else {
            panic!("Expected MessageParse error for out-of-order segment");
        }
    }

    #[test]
    fn test_max_remaining_segments_rejected_instead_of_overflowing() {
        let segment = MessageSegment::new(u8::MAX, Bytes::from_static(b"x"));
        let mut message = Message::new();
        assert!(message.add_segment(segment).is_err());
    }

    #[test]
    fn test_memory_efficient_allocation() {
        let segment_data = Bytes::from(vec![0u8; 100]);
        let mut message = Message::new();

        let segment = MessageSegment::new(9, segment_data.clone());
        message.add_segment(segment).unwrap();

        let capacity = message.data.capacity();
        assert!(capacity >= 1000, "Capacity {} too small", capacity);
        assert!(
            capacity <= 10 * MAX_MESSAGE_SIZE,
            "Capacity {} too large (over-allocation)",
            capacity
        );
    }
}

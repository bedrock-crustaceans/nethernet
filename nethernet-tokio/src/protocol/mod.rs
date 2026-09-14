//! Encoding and decoding of the NetherNet protocol.
//!
//! The wire formats live in the sans-IO crate and are re-exported here, while the
//! session description types below are built on the WebRTC types of this crate.

pub mod webrtc;

pub use nethernet::protocol::{
    Message, MessageSegment, Signal, SignalType, constants, message, packet, signal, types,
};
pub use webrtc::ConnectError;

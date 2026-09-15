//! WebRTC session-description validation helpers.

use crate::error::{NethernetError, Result};
use webrtc::peer_connection::RTCSessionDescription;

/// A validated SDP string exchanged by NetherNet signaling.
#[derive(Debug, Clone)]
pub struct Description {
    /// The original SDP text.
    pub sdp: String,
}

impl Description {
    /// Validate an SDP offer/answer and retain its wire representation.
    pub fn parse(sdp: &str) -> Result<Self> {
        if RTCSessionDescription::offer(sdp.to_string()).is_err()
            && RTCSessionDescription::answer(sdp.to_string()).is_err()
        {
            return Err(NethernetError::Other(
                "decode session description failed".into(),
            ));
        }
        Ok(Self {
            sdp: sdp.to_string(),
        })
    }

    /// Return the SDP wire representation.
    pub fn encode(&self) -> Result<String> {
        Ok(self.sdp.clone())
    }
}

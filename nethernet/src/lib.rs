//! Sans-IO implementation of the NetherNet protocol.
//!
//! Every type in this crate is driven by feeding it inputs and polling it for outputs,
//! so it performs no IO of its own and can be embedded in any runtime. The
//! `nethernet-tokio` crate drives these state machines on top of Tokio.

pub mod connection;
pub mod error;
pub mod identity;
pub mod protocol;
pub mod sans;
pub mod session;
pub mod signaling;
pub mod util;

pub mod prelude {
    pub use crate::error::{ProtocolError, SignalErrorCode};
    pub use crate::identity::{
        Identity, PlayerInfo, ServerIdentity, TokenTrust,
        error::IdentityError,
        jwk::{Jwk, JwkSet},
        jwt::Claims,
    };
    pub use crate::protocol::packet::discovery::{
        MessagePacket, Packets, RequestPacket, ResponsePacket, ServerData,
    };
    pub use crate::protocol::{Message, MessageSegment, NetherCodec, Signal, SignalType};
    pub use crate::sans::Sans;
    pub use crate::signaling::http::{
        HttpSignaler,
        config::HttpSignalerConfig,
        error::HttpSignalerError,
        input::{HttpSignalerInput, RejectReason},
        output::{HttpSignalerOutput, Offer},
    };
    pub use crate::signaling::lan::{
        LanSignaler, config::LanSignalerConfig, error::LanSignalerError, input::LanSignalerInput,
        output::LanSignalerOutput,
    };
    pub use crate::util::candidate;
    pub use crate::util::endpoint::{self, Scope};
    pub use crate::util::ip_range::IpRangeSet;
    pub use crate::util::proxy_protocol;
}

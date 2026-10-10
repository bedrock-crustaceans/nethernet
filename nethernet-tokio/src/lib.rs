//! Tokio transport for NetherNet: LAN and HTTP signaling, with client and server connections.
pub mod addr;
pub mod builders;
pub mod credentials;
pub mod error;
pub mod protocol;
pub mod session;
pub mod signaling;
pub mod transport;
pub mod util;

pub use addr::Addr;
pub use builders::*;
pub use credentials::{Credentials, IceServer};
pub use error::{NetherError, Result};
pub use nethernet::identity::{PlayerInfo, ServerIdentity, TokenTrust};
pub use protocol::packet::discovery::{MessagePacket, RequestPacket, ResponsePacket, ServerData};
pub use protocol::{Message, MessageSegment, Signal, SignalType};
pub use session::{AcceptedSession, Session, SessionReceiver};
pub use signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
pub use signaling::lan::{LanConfig, LanSignaling};
pub use signaling::{ClientSignaling, ServerSignaling};
pub use transport::{ConnectionConfig, NetherClient, NetherServer, Timeouts};

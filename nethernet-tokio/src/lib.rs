//! Tokio-based NetherNet protocol implementation.
//!
//! This crate provides high-level types for creating NetherNet clients and servers using WebRTC:
//! - [`NethernetStream`] for client connections
//! - [`NethernetListener`] for server-side connection acceptance
//! - [`Session`] for WebRTC peer connection management
//! - [`Signaling`] trait and its implementations, over LAN discovery and over HTTP

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
pub use error::{NethernetError, Result};
pub use nethernet::identity::{PlayerInfo, ServerIdentity, TokenTrust};
pub use protocol::packet::discovery::{MessagePacket, RequestPacket, ResponsePacket, ServerData};
pub use protocol::{ConnectError, Message, MessageSegment, Signal, SignalType};
pub use session::{AcceptedSession, Session, SessionReceiver};
pub use signaling::Signaling;
pub use signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
pub use signaling::lan::{LanConfig, LanSignaling};
pub use transport::{ConnectionConfig, NethernetListener, NethernetStream, Timeouts};

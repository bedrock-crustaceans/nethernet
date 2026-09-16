//! Negotiation protocol re-exports.
//!
//! The session descriptions, ICE candidate wire format and identity assertions are
//! sans-IO and live in the `nethernet` crate; only the wire error codes are specific to
//! this crate's `CONNECTERROR` handling.

mod error;

pub use error::ConnectError;
pub use nethernet::protocol::webrtc::candidate::{format_ice_candidate, parse_ice_candidate};
pub use nethernet::protocol::webrtc::{Description, DtlsRole};

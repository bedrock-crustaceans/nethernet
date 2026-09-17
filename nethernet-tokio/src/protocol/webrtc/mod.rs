//! Negotiation protocol re-exports.
//!
//! The session descriptions, ICE candidate wire format and identity assertions are all
//! sans-IO and live in the `nethernet` crate.

pub use nethernet::protocol::webrtc::candidate::{format_ice_candidate, parse_ice_candidate};
pub use nethernet::protocol::webrtc::{Description, DtlsRole};

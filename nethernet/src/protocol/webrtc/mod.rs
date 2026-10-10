//! SDP, ICE candidate and certificate handling for the single data-channel media section.
pub mod candidate;
pub mod certificate;
pub mod description;
pub mod identity;

pub use description::{Description, DtlsRole};

//! Signaling over the HTTP endpoints of dedicated servers.
//!
//! [`HttpSignaling`] dials such an endpoint, while [`HttpSignalingServer`] exposes one.

pub mod client;
pub mod server;

pub use client::HttpSignaling;
pub use server::{HttpServerConfig, HttpSignalingServer};

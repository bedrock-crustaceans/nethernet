//! HTTP signaling (guide section 4): a client posts the offer and the server's reply carries the answer.
pub mod client;
pub mod server;

pub use client::HttpSignaling;
pub use server::{HttpServerConfig, HttpSignalingServer};

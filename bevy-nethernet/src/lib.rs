//! Bevy plugins for NetherNet: LAN and HTTP servers and clients driven from the PreUpdate schedule.
mod connection;
mod http_stream;
mod http_wire;
mod socket;
mod tcp_wire;

pub mod client;
pub mod http_client;
pub mod http_server;
pub mod server;

pub mod prelude {
    pub use crate::client::{NetherClient, NetherClientEvent, NetherClientPlugin, NetherClientSet};
    pub use crate::http_client::{
        JoinError, NetherHttpClient, NetherHttpClientEvent, NetherHttpClientPlugin,
        NetherHttpClientSet, QueryError,
    };
    pub use crate::http_server::{
        NetherHttpServer, NetherHttpServerEvent, NetherHttpServerPlugin, NetherHttpServerSet,
    };
    pub use crate::server::{
        NetherServer, NetherServerEvent, NetherServerPlugin, NetherServerSet, NetherSessionId,
    };
    pub use nethernet::prelude::{
        HttpSignalerConfig, LanSignalerConfig, ServerData, ServerIdentity,
    };
}

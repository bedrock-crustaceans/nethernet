mod connection;
mod http_wire;
mod socket;

pub mod client;
pub mod http_client;
pub mod http_server;
pub mod server;

pub mod prelude {
    pub use crate::client::{NetherClient, NetherClientEvent, NetherClientPlugin, NetherClientSet};
    pub use crate::http_client::{
        NetherHttpClient, NetherHttpClientEvent, NetherHttpClientPlugin, NetherHttpClientSet,
    };
    pub use crate::http_server::{
        NetherHttpServer, NetherHttpServerEvent, NetherHttpServerPlugin, NetherHttpServerSet,
    };
    pub use crate::server::{
        NetherServer, NetherServerEvent, NetherServerPlugin, NetherServerSet, NetherSessionId,
    };
    pub use nethernet::prelude::{HttpSignalerConfig, LanSignalerConfig, ServerData};
}

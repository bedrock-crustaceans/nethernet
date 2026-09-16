mod connection;
mod http_wire;
mod socket;

pub mod client;
pub mod http_client;
pub mod http_server;
pub mod server;

pub mod prelude {
    pub use crate::client::{
        NethernetClient, NethernetClientEvent, NethernetClientPlugin, NethernetClientSet,
    };
    pub use crate::http_client::{
        NethernetHttpClient, NethernetHttpClientEvent, NethernetHttpClientPlugin,
        NethernetHttpClientSet,
    };
    pub use crate::http_server::{
        NethernetHttpServer, NethernetHttpServerEvent, NethernetHttpServerPlugin,
        NethernetHttpServerSet,
    };
    pub use crate::server::{
        NethernetServer, NethernetServerEvent, NethernetServerPlugin, NethernetServerSet,
        NethernetSessionId,
    };
    pub use nethernet::prelude::{HttpSignalerConfig, LanSignalerConfig, ServerData};
}

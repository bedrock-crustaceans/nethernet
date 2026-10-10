use crate::addr::Addr;
use crate::error::Result;
use crate::protocol::Signal;
use futures::Stream;
use http::{HttpSignaling, HttpSignalingServer};
use lan::LanSignaling;
use nethernet::identity::PlayerInfo;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

pub mod http;
pub mod lan;

#[derive(Clone)]
pub enum ServerSignaling {
    Lan(Arc<LanSignaling>),
    Http(Arc<HttpSignalingServer>),
}

impl From<LanSignaling> for ServerSignaling {
    fn from(signaling: LanSignaling) -> Self {
        Self::Lan(Arc::new(signaling))
    }
}

impl From<Arc<LanSignaling>> for ServerSignaling {
    fn from(signaling: Arc<LanSignaling>) -> Self {
        Self::Lan(signaling)
    }
}

impl From<HttpSignalingServer> for ServerSignaling {
    fn from(signaling: HttpSignalingServer) -> Self {
        Self::Http(Arc::new(signaling))
    }
}

impl From<Arc<HttpSignalingServer>> for ServerSignaling {
    fn from(signaling: Arc<HttpSignalingServer>) -> Self {
        Self::Http(signaling)
    }
}

impl ServerSignaling {
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        match self {
            Self::Lan(s) => s.signal(signal).await,
            Self::Http(s) => s.signal(signal).await,
        }
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        match self {
            Self::Lan(s) => s.signals(),
            Self::Http(s) => s.signals(),
        }
    }

    pub fn network_id(&self) -> String {
        match self {
            Self::Lan(s) => s.network_id(),
            Self::Http(s) => s.network_id(),
        }
    }

    pub fn disable_trickle_ice(&self) -> bool {
        match self {
            Self::Lan(s) => s.disable_trickle_ice(),
            Self::Http(s) => s.disable_trickle_ice(),
        }
    }

    pub async fn remote_address(&self, addr: &Addr) -> Option<SocketAddr> {
        match self {
            Self::Lan(s) => s.remote_address(addr).await,
            Self::Http(s) => s.remote_address(addr).await,
        }
    }

    pub async fn player(&self, addr: &Addr) -> Option<Arc<PlayerInfo>> {
        match self {
            Self::Lan(_) => None,
            Self::Http(s) => s.player(addr).await,
        }
    }

    pub async fn host(&self, addr: &Addr) -> Option<String> {
        match self {
            Self::Lan(_) => None,
            Self::Http(s) => s.host(addr).await,
        }
    }

    pub fn validates_offers(&self) -> bool {
        match self {
            Self::Lan(_) => false,
            Self::Http(_) => true,
        }
    }

    pub fn requires_identity(&self) -> bool {
        match self {
            Self::Lan(_) => false,
            Self::Http(_) => true,
        }
    }

    pub fn set_pong_data(&self, data: &[u8]) {
        match self {
            Self::Lan(s) => s.set_pong_data(data),
            Self::Http(s) => s.set_pong_data(data),
        }
    }
}

#[derive(Clone)]
pub enum ClientSignaling {
    Lan(Arc<LanSignaling>),
    Http(Arc<HttpSignaling>),
}

impl From<LanSignaling> for ClientSignaling {
    fn from(signaling: LanSignaling) -> Self {
        Self::Lan(Arc::new(signaling))
    }
}

impl From<Arc<LanSignaling>> for ClientSignaling {
    fn from(signaling: Arc<LanSignaling>) -> Self {
        Self::Lan(signaling)
    }
}

impl From<HttpSignaling> for ClientSignaling {
    fn from(signaling: HttpSignaling) -> Self {
        Self::Http(Arc::new(signaling))
    }
}

impl From<Arc<HttpSignaling>> for ClientSignaling {
    fn from(signaling: Arc<HttpSignaling>) -> Self {
        Self::Http(signaling)
    }
}

impl ClientSignaling {
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        match self {
            Self::Lan(s) => s.signal(signal).await,
            Self::Http(s) => s.signal(signal).await,
        }
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        match self {
            Self::Lan(s) => s.signals(),
            Self::Http(s) => s.signals(),
        }
    }

    pub fn network_id(&self) -> String {
        match self {
            Self::Lan(s) => s.network_id(),
            Self::Http(s) => s.network_id(),
        }
    }

    pub fn disable_trickle_ice(&self) -> bool {
        match self {
            Self::Lan(s) => s.disable_trickle_ice(),
            Self::Http(s) => s.disable_trickle_ice(),
        }
    }
}

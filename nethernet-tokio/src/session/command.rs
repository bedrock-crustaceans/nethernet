use crate::error::Result;
use crate::session::Channel;
use bytes::Bytes;
use nethernet::identity::PlayerInfo;
use nethernet::protocol::Signal;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

pub(crate) enum Command {
    Send(Channel, Bytes, oneshot::Sender<Result<()>>),
    Signal(Signal),
    RemoteAddr(oneshot::Sender<Option<SocketAddr>>),
    Rtt(oneshot::Sender<Option<Duration>>),
    SetPlayer(Arc<PlayerInfo>),
    Player(oneshot::Sender<Option<Arc<PlayerInfo>>>),
}

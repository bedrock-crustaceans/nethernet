//! One UDP socket serving every session of a server, each datagram routed to the session it belongs to.
use nethernet::util::stun;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const ROUTE_CHANNEL_CAPACITY: usize = 1024;

type Datagram = (Box<[u8]>, SocketAddr);

pub(crate) struct SharedSocket {
    socket: Arc<UdpSocket>,
    advertised: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    sessions: HashMap<u64, mpsc::Sender<Datagram>>,
    router: Router,
}

impl SharedSocket {
    /// An unspecified bind address is advertised as `advertised_ip` on the bound port.
    pub(crate) async fn bind(addr: SocketAddr, advertised_ip: IpAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let bound = socket.local_addr()?;
        let advertised = if bound.ip().is_unspecified() {
            SocketAddr::new(advertised_ip, bound.port())
        } else {
            bound
        };
        let state = Arc::new(Mutex::new(State::default()));
        let task = tokio::spawn(Self::dispatch(socket.clone(), state.clone()));
        Ok(Self {
            socket,
            advertised,
            state,
            task,
        })
    }

    /// The address answers name as the local candidate.
    pub(crate) fn advertised_addr(&self) -> SocketAddr {
        self.advertised
    }

    /// Registers a session reached through the STUN username fragment `local_ufrag`; the route keeps the socket open.
    pub(crate) fn route(self: &Arc<Self>, local_ufrag: String) -> SharedRoute {
        let (tx, rx) = mpsc::channel(ROUTE_CHANNEL_CAPACITY);
        let mut state = lock(&self.state);
        let id = state.next_id;
        state.next_id += 1;
        state.sessions.insert(id, tx);
        state.router.register_ufrag(local_ufrag.clone(), id);
        SharedRoute {
            id,
            local_ufrag,
            remote_addr: None,
            shared: self.clone(),
            packets: rx,
        }
    }

    async fn dispatch(socket: Arc<UdpSocket>, state: Arc<Mutex<State>>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(e) => {
                    tracing::debug!("recv error: {e}");
                    continue;
                }
            };
            let state = lock(&state);
            for id in state.router.route(from, &buf[..n]) {
                if let Some(tx) = state.sessions.get(&id) {
                    let _ = tx.try_send((buf[..n].into(), from));
                }
            }
        }
    }
}

impl Drop for SharedSocket {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One session's view of a shared socket; deregisters it when dropped.
pub(crate) struct SharedRoute {
    id: u64,
    local_ufrag: String,
    remote_addr: Option<SocketAddr>,
    shared: Arc<SharedSocket>,
    packets: mpsc::Receiver<Datagram>,
}

impl SharedRoute {
    pub(crate) async fn recv_from(&mut self) -> Option<Datagram> {
        self.packets.recv().await
    }

    pub(crate) async fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize> {
        if self.remote_addr.is_none() {
            lock(&self.shared.state).router.note_sent(to, self.id);
        }
        self.shared.socket.send_to(data, to).await
    }

    /// Routes everything from `addr` to this session once its pair is selected; retried while another session holds `addr`.
    pub(crate) fn claim(&mut self, addr: SocketAddr) {
        if self.remote_addr.is_none() && lock(&self.shared.state).router.claim_addr(addr, self.id) {
            self.remote_addr = Some(addr);
        }
    }
}

impl Drop for SharedRoute {
    fn drop(&mut self) {
        let mut state = lock(&self.shared.state);
        state.sessions.remove(&self.id);
        state
            .router
            .release(self.id, &self.local_ufrag, self.remote_addr);
    }
}

/// A dual-stack socket reports IPv4 peers as `::ffff:a.b.c.d`; keys use the plain form either way.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct Router {
    by_addr: HashMap<SocketAddr, u64>,
    provisional: HashMap<SocketAddr, HashSet<u64>>,
    by_ufrag: HashMap<String, u64>,
}

impl Router {
    fn route(&self, from: SocketAddr, datagram: &[u8]) -> Vec<u64> {
        let from = canonical(from);
        if let Some(id) = self.by_addr.get(&from) {
            return vec![*id];
        }
        if !stun::is_stun(datagram) {
            return Vec::new();
        }
        if let Some(ufrag) = stun::local_ufrag(datagram)
            && let Some(id) = self.by_ufrag.get(&ufrag)
        {
            return vec![*id];
        }
        self.provisional
            .get(&from)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    fn register_ufrag(&mut self, ufrag: String, id: u64) {
        self.by_ufrag.insert(ufrag, id);
    }

    /// Whether `id` owns `addr` afterwards; the first session to claim an address keeps it.
    fn claim_addr(&mut self, addr: SocketAddr, id: u64) -> bool {
        *self.by_addr.entry(canonical(addr)).or_insert(id) == id
    }

    fn note_sent(&mut self, addr: SocketAddr, id: u64) {
        self.provisional
            .entry(canonical(addr))
            .or_default()
            .insert(id);
    }

    fn release(&mut self, id: u64, ufrag: &str, addr: Option<SocketAddr>) {
        if self.by_ufrag.get(ufrag) == Some(&id) {
            self.by_ufrag.remove(ufrag);
        }
        if let Some(addr) = addr.map(canonical)
            && self.by_addr.get(&addr) == Some(&id)
        {
            self.by_addr.remove(&addr);
        }
        self.provisional.retain(|_, ids| {
            ids.remove(&id);
            !ids.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn stun(typ: u16, username: Option<&str>) -> Vec<u8> {
        let mut attributes = Vec::new();
        if let Some(username) = username {
            attributes.extend_from_slice(&0x0006u16.to_be_bytes());
            attributes.extend_from_slice(&(username.len() as u16).to_be_bytes());
            attributes.extend_from_slice(username.as_bytes());
            attributes.resize(attributes.len().next_multiple_of(4), 0);
        }
        let mut message = Vec::new();
        message.extend_from_slice(&typ.to_be_bytes());
        message.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        message.extend_from_slice(&0x2112_a442u32.to_be_bytes());
        message.extend_from_slice(&[7; 12]);
        message.extend_from_slice(&attributes);
        message
    }

    fn binding_request(username: &str) -> Vec<u8> {
        stun(0x0001, Some(username))
    }

    #[test]
    fn a_binding_request_reaches_the_session_owning_its_ufrag() {
        let mut router = Router::default();
        router.register_ufrag("first".into(), 1);
        router.register_ufrag("second".into(), 2);

        assert_eq!(
            router.route(addr(1), &binding_request("second:peer")),
            vec![2]
        );
        assert_eq!(
            router.route(addr(1), &binding_request("unknown:peer")),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn a_claimed_address_routes_every_datagram() {
        let mut router = Router::default();
        router.claim_addr(addr(1), 7);

        assert_eq!(router.route(addr(1), b"dtls"), vec![7]);
        assert_eq!(router.route(addr(2), b"dtls"), Vec::<u64>::new());
    }

    #[test]
    fn a_reply_without_a_username_reaches_the_sessions_that_sent_to_its_address() {
        let mut router = Router::default();
        router.note_sent(addr(1), 3);

        assert_eq!(router.route(addr(1), &stun(0x0101, None)), vec![3]);
        assert_eq!(router.route(addr(1), b"dtls"), Vec::<u64>::new());
    }

    #[test]
    fn a_mapped_reply_reaches_the_session_that_sent_to_the_plain_address() {
        let mut router = Router::default();
        router.note_sent(addr(1), 5);
        let mapped = SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 1));

        assert_eq!(router.route(mapped, &stun(0x0101, None)), vec![5]);
    }

    #[test]
    fn a_claimed_address_matches_its_mapped_form() {
        let mut router = Router::default();
        let mapped = SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 1));
        assert!(router.claim_addr(mapped, 6));

        assert_eq!(router.route(addr(1), b"dtls"), vec![6]);
        router.release(6, "", Some(addr(1)));
        assert!(router.route(mapped, b"dtls").is_empty());
    }

    #[test]
    fn an_address_owned_by_another_session_is_not_claimed_until_released() {
        let mut router = Router::default();
        assert!(router.claim_addr(addr(1), 1));
        assert!(!router.claim_addr(addr(1), 2));
        assert_eq!(router.route(addr(1), b"dtls"), vec![1]);

        router.release(1, "", Some(addr(1)));
        assert!(router.claim_addr(addr(1), 2));
        assert_eq!(router.route(addr(1), b"dtls"), vec![2]);
    }

    #[test]
    fn a_released_session_receives_nothing() {
        let mut router = Router::default();
        router.register_ufrag("ufrag".into(), 4);
        router.claim_addr(addr(1), 4);
        router.note_sent(addr(2), 4);

        router.release(4, "ufrag", Some(addr(1)));

        assert!(
            router
                .route(addr(1), &binding_request("ufrag:peer"))
                .is_empty()
        );
        assert!(router.route(addr(2), &binding_request("x:y")).is_empty());
    }
}

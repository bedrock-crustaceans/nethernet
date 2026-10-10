use async_channel::{Receiver, Sender, TryRecvError};
use nethernet::connection::{Connection, ConnectionInput};
use nethernet::protocol::Signal;
use nethernet::sans::Sans;
use nethernet::session::{Channel, SessionEvent, SessionOutput};
use nethernet::util::stun;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);

const MAX_IDLE: Duration = Duration::from_secs(1);

const RTT_REPORT_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) enum ConnectionEvent {
    Ready(Option<SocketAddr>),
    Rtt(Duration),
    Message(Channel, Box<[u8]>),
    Failed,
}

enum Command<K> {
    Add(K, Box<Connection>, String, Sender<()>),
    Signal(K, Signal),
    Send(K, Channel, Box<[u8]>),
    Remove(K),
}

pub(crate) struct SessionPool<K> {
    commands: Sender<Command<K>>,
    events: Receiver<(K, ConnectionEvent)>,
}

impl<K> SessionPool<K>
where
    K: Eq + Hash + Clone + Send + 'static,
{
    pub(crate) fn new(socket: UdpSocket) -> Self {
        let (command_tx, command_rx) = async_channel::unbounded();
        let (event_tx, event_rx) = async_channel::unbounded();

        std::thread::Builder::new()
            .name("nethernet-session-pool".to_string())
            .spawn(move || drive(socket, command_rx, event_tx))
            .expect("failed to spawn the session pool's thread");

        Self {
            commands: command_tx,
            events: event_rx,
        }
    }

    pub(crate) fn add(&mut self, id: K, connection: Connection, local_ufrag: String) {
        let (ack_tx, ack_rx) = async_channel::bounded(1);
        let _ = self
            .commands
            .try_send(Command::Add(id, Box::new(connection), local_ufrag, ack_tx));
        let _ = ack_rx.recv_blocking();
    }

    pub(crate) fn remove(&mut self, id: K) {
        let _ = self.commands.try_send(Command::Remove(id));
    }

    pub(crate) fn signal(&mut self, id: K, signal: &Signal) {
        let _ = self.commands.try_send(Command::Signal(id, signal.clone()));
    }

    pub(crate) fn send(&mut self, id: K, channel: Channel, data: Box<[u8]>) {
        let _ = self.commands.try_send(Command::Send(id, channel, data));
    }

    pub(crate) fn drive(&mut self, events: &mut Vec<(K, ConnectionEvent)>) {
        loop {
            match self.events.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Closed) => return,
            }
        }
    }
}

struct Entry {
    connection: Connection,
    local_ufrag: String,
    remote_addr: Option<SocketAddr>,
    wait: Instant,
    reported_rtt: Option<Duration>,
    rtt_reported_at: Option<Instant>,
}

fn drive<K: Eq + Hash + Clone>(
    socket: UdpSocket,
    commands: Receiver<Command<K>>,
    events: Sender<(K, ConnectionEvent)>,
) {
    let mut buf = vec![0u8; 65536];
    let mut entries: HashMap<K, Entry> = HashMap::new();
    let mut by_addr: HashMap<SocketAddr, K> = HashMap::new();
    let mut by_ufrag: HashMap<String, K> = HashMap::new();

    loop {
        let now = Instant::now();
        let next_wait = entries
            .values()
            .map(|entry| entry.wait.saturating_duration_since(now))
            .min()
            .unwrap_or(MAX_IDLE);
        let timeout = next_wait
            .min(COMMAND_POLL_INTERVAL)
            .max(Duration::from_millis(1));
        if socket.set_read_timeout(Some(timeout)).is_err() {
            return;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let id = by_addr.get(&from).cloned().or_else(|| {
                    stun::local_ufrag(&buf[..len]).and_then(|ufrag| by_ufrag.get(&ufrag).cloned())
                });
                if let Some(id) = id
                    && let Some(entry) = entries.get_mut(&id)
                {
                    let now = Instant::now();
                    let input = ConnectionInput::Packet(buf[..len].into(), from, now);
                    if let Err(e) = entry.connection.handle(input) {
                        tracing::debug!("packet handling error: {e}");
                    }
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => tracing::debug!("recv error: {e}"),
        }

        loop {
            match commands.try_recv() {
                Ok(Command::Add(id, connection, local_ufrag, ack)) => {
                    by_ufrag.insert(local_ufrag.clone(), id.clone());
                    entries.insert(
                        id,
                        Entry {
                            connection: *connection,
                            local_ufrag,
                            remote_addr: None,
                            wait: Instant::now(),
                            reported_rtt: None,
                            rtt_reported_at: None,
                        },
                    );
                    let _ = ack.try_send(());
                }
                Ok(Command::Remove(id)) => {
                    if let Some(entry) = entries.remove(&id) {
                        by_ufrag.remove(&entry.local_ufrag);
                        if let Some(addr) = entry.remote_addr {
                            by_addr.remove(&addr);
                        }
                    }
                }
                Ok(Command::Signal(id, signal)) => {
                    if let Some(entry) = entries.get_mut(&id)
                        && let Err(e) = entry
                            .connection
                            .handle(ConnectionInput::Signal(signal, now))
                    {
                        tracing::debug!("signal handling error: {e}");
                    }
                }
                Ok(Command::Send(id, channel, data)) => {
                    if let Some(entry) = entries.get_mut(&id) {
                        let input = ConnectionInput::Send(channel, data.into(), now);
                        if let Err(e) = entry.connection.handle(input) {
                            tracing::debug!("send error: {e}");
                        }
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => return,
            }
        }

        let now = Instant::now();
        let mut failed = Vec::new();
        for (id, entry) in entries.iter_mut() {
            if let Err(e) = entry.connection.handle(ConnectionInput::Timeout(now)) {
                tracing::debug!("timeout handling error: {e}");
            }

            if entry.remote_addr.is_none()
                && let Some(addr) = entry.connection.remote_addr()
            {
                entry.remote_addr = Some(addr);
                by_addr.insert(addr, id.clone());
            }

            while let Some(output) = entry.connection.poll() {
                match output {
                    SessionOutput::Send(data, to) => {
                        let _ = socket.send_to(&data, to);
                    }
                    SessionOutput::Event(SessionEvent::Ready) => {
                        let ready = ConnectionEvent::Ready(entry.connection.remote_addr());
                        if events.try_send((id.clone(), ready)).is_err() {
                            return;
                        }
                    }
                    SessionOutput::Event(SessionEvent::Failed) => failed.push(id.clone()),
                    SessionOutput::Message(channel, data) => {
                        let message = ConnectionEvent::Message(channel, data.into_boxed_slice());
                        if events.try_send((id.clone(), message)).is_err() {
                            return;
                        }
                    }
                    SessionOutput::Wait(wait) => entry.wait = now + wait,
                }
            }

            if let Some(rtt) = entry.connection.rtt()
                && entry.reported_rtt != Some(rtt)
                && entry
                    .rtt_reported_at
                    .is_none_or(|at| now.saturating_duration_since(at) >= RTT_REPORT_INTERVAL)
            {
                entry.reported_rtt = Some(rtt);
                entry.rtt_reported_at = Some(now);
                if events
                    .try_send((id.clone(), ConnectionEvent::Rtt(rtt)))
                    .is_err()
                {
                    return;
                }
            }
        }

        for id in failed {
            if let Some(entry) = entries.remove(&id) {
                by_ufrag.remove(&entry.local_ufrag);
                if let Some(addr) = entry.remote_addr {
                    by_addr.remove(&addr);
                }
            }
            if events.try_send((id, ConnectionEvent::Failed)).is_err() {
                return;
            }
        }
    }
}

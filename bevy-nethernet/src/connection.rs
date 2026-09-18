//! Drives every [`Connection`] of a client or server on one dedicated background
//! thread, sharing a single socket between them - the same way RakNet's own server
//! does it - instead of giving each its own socket and thread.
//!
//! This thread runs for as long as the pool exists, not the short blocking-then-done
//! shape `bevy_tasks::IoTaskPool` is meant for, so it's a plain [`std::thread`] rather
//! than a pool task: there's exactly one (or two, client and server) per app, not one
//! per connection, so there's nothing to size a pool for.
//!
//! Routing an inbound datagram to the right [`Connection`] needs the remote address
//! ICE eventually settles on, which isn't known yet for a connection still handshaking;
//! until then, a datagram is routed by the local ICE ufrag its STUN `USERNAME`
//! attribute names (see [`nethernet::util::stun`]), which is known from the moment the
//! connection is created.

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

/// Caps how long `recv_from` blocks before checking for a queued command, regardless
/// of any session's [`SessionOutput::Wait`] - otherwise a long wait could delay a
/// queued [`SessionPool::send`]/[`SessionPool::signal`]/[`SessionPool::add`] just as
/// long.
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Longest the task ever blocks when no session has reported a real
/// [`SessionOutput::Wait`] yet.
const MAX_IDLE: Duration = Duration::from_secs(1);

pub(crate) enum ConnectionEvent {
    Ready,
    Message(Channel, Box<[u8]>),
    Failed,
}

enum Command<K> {
    Add(K, Box<Connection>, String, Sender<()>),
    Signal(K, Signal),
    Send(K, Channel, Box<[u8]>),
    Remove(K),
}

/// A handle to every [`Connection`] of one client or server, all driven on a shared
/// socket by one background task. Dropping it closes the command channel, which the
/// task takes as its cue to stop.
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

    /// Adds a connection to drive, identified by `id` from now on. `local_ufrag` is
    /// the `ufrag` of the [`nethernet::protocol::webrtc::Description`] this connection
    /// was created from, which is how an inbound datagram is routed to it before its
    /// remote address is known.
    ///
    /// Blocks until the background task confirms the connection is actually routable
    /// (bounded by [`COMMAND_POLL_INTERVAL`]): the caller signals the offer/answer
    /// right after this returns, and the remote peer's first datagram can arrive before
    /// the task would otherwise have gotten around to registering it, which - since
    /// nothing resends a dropped STUN check for a good while - is exactly the kind of
    /// thing this pool exists to not add latency to.
    pub(crate) fn add(&mut self, id: K, connection: Connection, local_ufrag: String) {
        let (ack_tx, ack_rx) = async_channel::bounded(1);
        let _ = self
            .commands
            .try_send(Command::Add(id, Box::new(connection), local_ufrag, ack_tx));
        let _ = ack_rx.recv_blocking();
    }

    /// Stops driving a connection, dropping whatever of it the background task still
    /// holds.
    pub(crate) fn remove(&mut self, id: K) {
        let _ = self.commands.try_send(Command::Remove(id));
    }

    /// Queues a signal for the background task to apply to the named connection.
    pub(crate) fn signal(&mut self, id: K, signal: &Signal) {
        let _ = self.commands.try_send(Command::Signal(id, signal.clone()));
    }

    /// Queues a complete application message for the background task to send on the
    /// named connection.
    pub(crate) fn send(&mut self, id: K, channel: Channel, data: Box<[u8]>) {
        let _ = self.commands.try_send(Command::Send(id, channel, data));
    }

    /// Drains events the background task has produced since the last call.
    pub(crate) fn drive(&mut self, events: &mut Vec<(K, ConnectionEvent)>) {
        loop {
            match self.events.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => return,
                // The pool's task stopped; every connection it held is gone with it,
                // but there's no `id` left to report that against individually.
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
}

/// Owns the shared socket and every session, blocking on `recv_from` until a datagram
/// arrives, a command does, or the soonest session's wait deadline passes.
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
                        && let Err(e) = entry.connection.handle(ConnectionInput::Signal(signal))
                    {
                        tracing::debug!("signal handling error: {e}");
                    }
                }
                Ok(Command::Send(id, channel, data)) => {
                    if let Some(entry) = entries.get_mut(&id) {
                        let input = ConnectionInput::Send(channel, data.into());
                        if let Err(e) = entry.connection.handle(input) {
                            tracing::debug!("send error: {e}");
                        }
                    }
                }
                Err(TryRecvError::Empty) => break,
                // The pool was dropped: nothing left to drive.
                Err(TryRecvError::Closed) => return,
            }
        }

        let now = Instant::now();
        let mut failed = Vec::new();
        for (id, entry) in entries.iter_mut() {
            // `entry.wait` only caps how long `recv_from` may block, the same as
            // `COMMAND_POLL_INTERVAL` - it isn't a deadline gating this call. A
            // connection's own internal pacing (e.g. ICE checklist scheduling) expects
            // `Timeout` every time the driver comes back around, not just once its
            // last reported `Wait` has elapsed.
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
                        if events
                            .try_send((id.clone(), ConnectionEvent::Ready))
                            .is_err()
                        {
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

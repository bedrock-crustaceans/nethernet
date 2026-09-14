//! Signaling over the LAN discovery protocol.
//!
//! Servers answer the requests clients broadcast to the discovery port, and both sides
//! carry their offers, answers and candidates in the message packets that follow. The
//! state machine below owns the address table, the broadcasts and the retransmissions,
//! and leaves every socket operation to its caller.

pub mod config;
pub mod error;
pub mod input;
pub mod output;

use crate::protocol::packet::discovery::{
    MessagePacket, RequestPacket, ResponsePacket, ServerData, marshal, unmarshal,
};
use crate::protocol::{Signal, constants};
use crate::sans::Sans;
use config::LanSignalerConfig;
use error::LanSignalerError;
use input::LanSignalerInput;
use output::LanSignalerOutput;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Keepalive clients broadcast between their discovery requests. It is not a negotiation
/// signal and carries nothing to act on.
const PING: &str = "Ping";

/// The signaling of a single NetherNet network on the local network.
pub struct LanSignaler {
    network_id: u64,
    config: LanSignalerConfig,

    addresses: HashMap<u64, AddressEntry>,
    discovered: HashMap<u64, ServerData>,
    pending: Vec<PendingSignal>,
    server_data: Option<ServerData>,

    last_broadcast: Option<Instant>,
    last_cleanup: Option<Instant>,

    output: VecDeque<LanSignalerOutput>,
}

#[derive(Debug, Clone, Copy)]
struct AddressEntry {
    addr: SocketAddr,
    last_seen: Instant,
}

#[derive(Debug, Clone)]
struct PendingSignal {
    signal: Signal,
    target: u64,
    attempts: u32,
    next_send: Instant,
}

impl Sans for LanSignaler {
    type Input = LanSignalerInput;
    type Output = LanSignalerOutput;
    type Error = LanSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            LanSignalerInput::Datagram(buf, addr, now) => self.handle_datagram(&buf, addr, now)?,
            LanSignalerInput::Signal(signal, now) => self.handle_signal(signal, now)?,
            LanSignalerInput::SetServerData(data) => self.server_data = Some(*data),
            LanSignalerInput::Update(now) => self.handle_update(now)?,
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl LanSignaler {
    /// Creates the signaling of the network with the given ID.
    pub fn new(network_id: u64, config: LanSignalerConfig) -> Self {
        Self {
            network_id,
            config,
            addresses: HashMap::new(),
            discovered: HashMap::new(),
            pending: Vec::new(),
            server_data: None,
            last_broadcast: None,
            last_cleanup: None,
            output: VecDeque::new(),
        }
    }

    /// The ID of the local network.
    pub fn network_id(&self) -> u64 {
        self.network_id
    }

    /// The servers that have answered a discovery request, keyed by their network ID.
    pub fn discovered(&self) -> &HashMap<u64, ServerData> {
        &self.discovered
    }

    /// The address a remote network was last seen at.
    pub fn address(&self, network_id: u64) -> Option<SocketAddr> {
        self.addresses.get(&network_id).map(|entry| entry.addr)
    }

    /// The signals that are still waiting to be answered.
    pub fn pending_signals(&self) -> usize {
        self.pending.len()
    }

    fn handle_datagram(
        &mut self,
        buf: &[u8],
        addr: SocketAddr,
        now: Instant,
    ) -> Result<(), LanSignalerError> {
        // Anything that is not a discovery packet belongs to another service on the port
        let Ok((packet, sender)) = unmarshal(buf) else {
            tracing::trace!("ignoring unrecognized packet from {}", addr);
            return Ok(());
        };

        if sender == self.network_id {
            return Ok(());
        }

        self.addresses.insert(
            sender,
            AddressEntry {
                addr,
                last_seen: now,
            },
        );

        match packet.id() {
            constants::ID_REQUEST_PACKET => self.answer_request(addr)?,
            constants::ID_RESPONSE_PACKET => {
                let Some(response) = packet.as_any().downcast_ref::<ResponsePacket>() else {
                    return Ok(());
                };

                if let Ok(data) = ServerData::unmarshal(&response.application_data) {
                    self.discovered.insert(sender, data.clone());
                    self.output
                        .push_back(LanSignalerOutput::ServerDiscovered(sender, Box::new(data)));
                }
            }
            constants::ID_MESSAGE_PACKET => {
                let Some(message) = packet.as_any().downcast_ref::<MessagePacket>() else {
                    return Ok(());
                };

                if message.data == PING || message.recipient_id != self.network_id {
                    return Ok(());
                }

                let Ok(signal) = Signal::from_string(&message.data, sender.to_string()) else {
                    tracing::debug!("ignoring malformed signal from {}", sender);
                    return Ok(());
                };

                // The remote connection answered, so nothing has to be retransmitted for it
                self.pending
                    .retain(|pending| {
                        pending.target != sender
                            || pending.signal.connection_id != signal.connection_id
                    });

                self.output.push_back(LanSignalerOutput::Signal(signal));
            }
            id => tracing::debug!("unknown discovery packet {}", id),
        }

        Ok(())
    }

    fn answer_request(&mut self, addr: SocketAddr) -> Result<(), LanSignalerError> {
        let Some(data) = self.server_data.as_ref() else {
            tracing::debug!("no server data configured, not answering {}", addr);
            return Ok(());
        };

        let response = ResponsePacket::new(data.marshal()?);
        let buf = marshal(&response, self.network_id)?;
        self.output
            .push_back(LanSignalerOutput::Datagram(buf.into(), addr));

        Ok(())
    }

    fn handle_signal(&mut self, signal: Signal, now: Instant) -> Result<(), LanSignalerError> {
        let target = signal
            .network_id
            .parse::<u64>()
            .map_err(|_| LanSignalerError::InvalidNetworkId(signal.network_id.clone()))?;

        self.send_signal(&signal, target)?;

        if self.config.signal_retries > 0 {
            self.pending.push(PendingSignal {
                signal,
                target,
                attempts: 1,
                next_send: now + self.config.signal_retry_interval,
            });
        }

        Ok(())
    }

    fn send_signal(&mut self, signal: &Signal, target: u64) -> Result<(), LanSignalerError> {
        let addr = self
            .addresses
            .get(&target)
            .map(|entry| entry.addr)
            .ok_or(LanSignalerError::UnknownNetwork(target))?;

        let message = MessagePacket::new(target, signal.to_string());
        let buf = marshal(&message, self.network_id)?;
        self.output
            .push_back(LanSignalerOutput::Datagram(buf.into(), addr));

        Ok(())
    }

    fn handle_update(&mut self, now: Instant) -> Result<(), LanSignalerError> {
        self.retransmit(now)?;
        self.broadcast(now)?;
        self.expire(now);

        let wait = self.next_timer(now);
        self.output.push_back(LanSignalerOutput::Wait(wait));

        Ok(())
    }

    fn retransmit(&mut self, now: Instant) -> Result<(), LanSignalerError> {
        let retries = self.config.signal_retries;
        let interval = self.config.signal_retry_interval;

        let mut due = Vec::new();
        self.pending.retain_mut(|pending| {
            if pending.next_send > now {
                return true;
            }
            if pending.attempts > retries {
                return false;
            }

            due.push((pending.signal.clone(), pending.target));
            pending.attempts += 1;
            pending.next_send = now + interval;
            true
        });

        for (signal, target) in due {
            // The address may have expired since the signal was queued
            if self.send_signal(&signal, target).is_err() {
                self.pending
                    .retain(|pending| pending.target != target || pending.signal != signal);
            }
        }

        Ok(())
    }

    fn broadcast(&mut self, now: Instant) -> Result<(), LanSignalerError> {
        let Some(addr) = self.config.broadcast_address else {
            return Ok(());
        };

        let due = match self.last_broadcast {
            Some(last) => now.duration_since(last) >= self.config.broadcast_interval,
            None => true,
        };
        if !due {
            return Ok(());
        }

        let buf = marshal(&RequestPacket, self.network_id)?;
        self.output
            .push_back(LanSignalerOutput::Datagram(buf.into(), addr));
        self.last_broadcast = Some(now);

        Ok(())
    }

    fn expire(&mut self, now: Instant) {
        let timeout = self.config.address_timeout;
        self.addresses
            .retain(|_, entry| now.duration_since(entry.last_seen) < timeout);
        self.last_cleanup = Some(now);
    }

    /// How long the caller may wait before the next broadcast or retransmission is due.
    fn next_timer(&self, now: Instant) -> Duration {
        let mut wait = self.config.address_timeout;

        if self.config.broadcast_address.is_some() {
            let next = match self.last_broadcast {
                Some(last) => (last + self.config.broadcast_interval).saturating_duration_since(now),
                None => Duration::ZERO,
            };
            wait = wait.min(next);
        }

        for pending in &self.pending {
            wait = wait.min(pending.next_send.saturating_duration_since(now));
        }

        wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SignalType;

    const CLIENT: u64 = 1;
    const SERVER: u64 = 2;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn client(config: LanSignalerConfig) -> LanSignaler {
        LanSignaler::new(CLIENT, config)
    }

    fn server() -> LanSignaler {
        let mut signaler = LanSignaler::new(SERVER, LanSignalerConfig::default());
        signaler
            .handle(LanSignalerInput::SetServerData(Box::new(ServerData::new(
                "Server".to_string(),
                "World".to_string(),
            ))))
            .unwrap();
        signaler
    }

    fn datagrams(signaler: &mut LanSignaler) -> Vec<(Box<[u8]>, SocketAddr)> {
        let mut out = Vec::new();
        while let Some(output) = signaler.poll() {
            if let LanSignalerOutput::Datagram(buf, addr) = output {
                out.push((buf, addr));
            }
        }
        out
    }

    #[test]
    fn a_request_is_broadcast_on_the_first_update() {
        let mut signaler = client(LanSignalerConfig {
            broadcast_address: Some(addr(7551)),
            ..Default::default()
        });

        signaler.handle(LanSignalerInput::Update(Instant::now())).unwrap();

        let sent = datagrams(&mut signaler);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, addr(7551));
    }

    #[test]
    fn a_server_answers_a_request_with_its_data() {
        let now = Instant::now();
        let mut client = client(LanSignalerConfig::default());
        let mut server = server();

        let request = marshal(&RequestPacket, CLIENT).unwrap();
        server
            .handle(LanSignalerInput::Datagram(
                request.into(),
                addr(40000),
                now,
            ))
            .unwrap();

        let sent = datagrams(&mut server);
        assert_eq!(sent.len(), 1);

        client
            .handle(LanSignalerInput::Datagram(
                sent[0].0.clone(),
                addr(7551),
                now,
            ))
            .unwrap();

        let discovered = client
            .poll()
            .expect("the response should be reported");
        assert!(matches!(
            discovered,
            LanSignalerOutput::ServerDiscovered(SERVER, _)
        ));
        assert_eq!(client.address(SERVER), Some(addr(7551)));
    }

    #[test]
    fn a_signal_reaches_the_network_it_names() {
        let now = Instant::now();
        let mut client = client(LanSignalerConfig::default());
        let mut server = server();

        let request = marshal(&RequestPacket, SERVER).unwrap();
        client
            .handle(LanSignalerInput::Datagram(request.into(), addr(7551), now))
            .unwrap();
        let _ = datagrams(&mut client);

        client
            .handle(LanSignalerInput::Signal(
                Signal::offer(42, "sdp".to_string(), SERVER.to_string()),
                now,
            ))
            .unwrap();

        let sent = datagrams(&mut client);
        assert_eq!(sent.len(), 1);

        server
            .handle(LanSignalerInput::Datagram(
                sent[0].0.clone(),
                addr(40000),
                now,
            ))
            .unwrap();

        let LanSignalerOutput::Signal(signal) = server.poll().expect("a signal") else {
            panic!("expected a signal");
        };
        assert_eq!(signal.signal_type, SignalType::Offer);
        assert_eq!(signal.connection_id, 42);
        assert_eq!(signal.network_id, CLIENT.to_string());
    }

    #[test]
    fn a_signal_to_an_unknown_network_is_refused() {
        let mut client = client(LanSignalerConfig::default());

        let error = client
            .handle(LanSignalerInput::Signal(
                Signal::offer(42, "sdp".to_string(), SERVER.to_string()),
                Instant::now(),
            ))
            .unwrap_err();

        assert!(matches!(error, LanSignalerError::UnknownNetwork(SERVER)));
    }

    #[test]
    fn an_unanswered_signal_is_retransmitted_until_it_is_given_up_on() {
        let now = Instant::now();
        let config = LanSignalerConfig {
            signal_retries: 2,
            signal_retry_interval: Duration::from_millis(100),
            ..Default::default()
        };
        let mut client = client(config);

        let request = marshal(&RequestPacket, SERVER).unwrap();
        client
            .handle(LanSignalerInput::Datagram(request.into(), addr(7551), now))
            .unwrap();
        let _ = datagrams(&mut client);

        client
            .handle(LanSignalerInput::Signal(
                Signal::offer(42, "sdp".to_string(), SERVER.to_string()),
                now,
            ))
            .unwrap();
        assert_eq!(datagrams(&mut client).len(), 1);

        for step in 1..=2 {
            let now = now + Duration::from_millis(100 * step);
            client.handle(LanSignalerInput::Update(now)).unwrap();
            assert_eq!(datagrams(&mut client).len(), 1, "step {}", step);
        }

        client
            .handle(LanSignalerInput::Update(now + Duration::from_millis(300)))
            .unwrap();
        assert!(datagrams(&mut client).is_empty());
        assert_eq!(client.pending_signals(), 0);
    }

    #[test]
    fn an_answered_signal_is_not_retransmitted() {
        let now = Instant::now();
        let config = LanSignalerConfig {
            signal_retry_interval: Duration::from_millis(100),
            ..Default::default()
        };
        let mut client = client(config);

        let request = marshal(&RequestPacket, SERVER).unwrap();
        client
            .handle(LanSignalerInput::Datagram(request.into(), addr(7551), now))
            .unwrap();
        let _ = datagrams(&mut client);

        client
            .handle(LanSignalerInput::Signal(
                Signal::offer(42, "sdp".to_string(), SERVER.to_string()),
                now,
            ))
            .unwrap();
        let _ = datagrams(&mut client);

        let answer = MessagePacket::new(
            CLIENT,
            Signal::answer(42, "sdp".to_string(), CLIENT.to_string()).to_string(),
        );
        let buf = marshal(&answer, SERVER).unwrap();
        client
            .handle(LanSignalerInput::Datagram(buf.into(), addr(7551), now))
            .unwrap();

        assert_eq!(client.pending_signals(), 0);

        client
            .handle(LanSignalerInput::Update(now + Duration::from_millis(200)))
            .unwrap();
        assert!(datagrams(&mut client).is_empty());
    }

    #[test]
    fn an_address_is_forgotten_once_it_goes_quiet() {
        let now = Instant::now();
        let mut client = client(LanSignalerConfig {
            address_timeout: Duration::from_secs(5),
            ..Default::default()
        });

        let request = marshal(&RequestPacket, SERVER).unwrap();
        client
            .handle(LanSignalerInput::Datagram(request.into(), addr(7551), now))
            .unwrap();
        assert!(client.address(SERVER).is_some());

        client
            .handle(LanSignalerInput::Update(now + Duration::from_secs(6)))
            .unwrap();
        assert!(client.address(SERVER).is_none());
    }

    #[test]
    fn a_ping_is_not_reported_as_a_signal() {
        let now = Instant::now();
        let mut client = client(LanSignalerConfig::default());

        let ping = MessagePacket::new(CLIENT, PING.to_string());
        let buf = marshal(&ping, SERVER).unwrap();
        client
            .handle(LanSignalerInput::Datagram(buf.into(), addr(7551), now))
            .unwrap();

        assert!(client.poll().is_none());
    }
}

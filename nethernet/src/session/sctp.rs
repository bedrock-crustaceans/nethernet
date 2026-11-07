//! SCTP association over DTLS on the fixed NetherNet port.
use crate::error::ProtocolError;
use crate::session::dtls::ResolvedRole;
use bytes::Bytes;
pub use rtc::sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, ServerConfig, TransportConfig,
};
use rtc::shared::TransportProtocol;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const SCTP_PORT: u16 = 5000;

const SERVER_INIT_FALLBACK: Duration = Duration::from_secs(2);

pub struct SctpLayer {
    endpoint: Endpoint,
    remote_addr: SocketAddr,
    association: Option<(AssociationHandle, Association)>,
    fallback_init: Option<(Instant, TransportConfig)>,
    pending_transmits: VecDeque<Vec<u8>>,
}

impl SctpLayer {
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        role: ResolvedRole,
        max_message_size: u32,
        now: Instant,
    ) -> Result<SctpLayer, ProtocolError> {
        let transport = TransportConfig::default()
            .with_sctp_port(SCTP_PORT)
            .with_max_message_size(max_message_size);

        let mut endpoint = Endpoint::new(
            local_addr,
            TransportProtocol::UDP,
            Arc::new(EndpointConfig::new()),
            (role == ResolvedRole::Server).then(|| Arc::new(ServerConfig::new(transport.clone()))),
        );

        let (association, fallback_init) = match role {
            ResolvedRole::Client => {
                let (handle, assoc) = endpoint
                    .connect(now, ClientConfig::new(transport), remote_addr)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                (Some((handle, assoc)), None)
            }
            ResolvedRole::Server => (None, Some((now + SERVER_INIT_FALLBACK, transport))),
        };

        Ok(Self {
            endpoint,
            remote_addr,
            association,
            fallback_init,
            pending_transmits: VecDeque::new(),
        })
    }

    pub fn handle_read(&mut self, data: &[u8], now: Instant) {
        let Some((handle, event)) =
            self.endpoint
                .handle(now, self.remote_addr, None, Bytes::copy_from_slice(data))
        else {
            return;
        };

        match event {
            DatagramEvent::NewAssociation(assoc) => {
                self.fallback_init = None;
                self.association = Some((handle, assoc));
            }
            DatagramEvent::AssociationEvent(event) => {
                if let Some((_, assoc)) = &mut self.association {
                    assoc.handle_event(event);
                }
            }
            _ => {}
        }
    }

    pub fn association_mut(&mut self) -> Option<&mut Association> {
        self.association.as_mut().map(|(_, assoc)| assoc)
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.association.as_ref().map(|(_, assoc)| assoc.rtt())
    }

    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        if let Some(data) = self.pending_transmits.pop_front() {
            return Some(data);
        }

        let (_, assoc) = self.association.as_mut()?;
        let transmit = assoc.poll_transmit(now)?;
        let Payload::RawEncode(packets) = transmit.message else {
            return None;
        };
        self.pending_transmits
            .extend(packets.into_iter().map(|b| b.to_vec()));
        self.pending_transmits.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.association
            .as_mut()
            .and_then(|(_, assoc)| assoc.poll())
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.start_fallback_init(now);
        if let Some((handle, assoc)) = &mut self.association {
            assoc.handle_timeout(now);
            while let Some(event) = assoc.poll_endpoint_event() {
                self.endpoint.handle_event(*handle, event);
            }
        }
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        let association = self
            .association
            .as_ref()
            .and_then(|(_, assoc)| assoc.poll_timeout());
        let fallback = self.fallback_init.as_ref().map(|(at, _)| *at);
        match (association, fallback) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn start_fallback_init(&mut self, now: Instant) {
        if self.association.is_some() {
            self.fallback_init = None;
            return;
        }
        let Some((at, _)) = &self.fallback_init else {
            return;
        };
        if now < *at {
            return;
        }
        let Some((_, transport)) = self.fallback_init.take() else {
            return;
        };
        if let Ok((handle, assoc)) =
            self.endpoint
                .connect(now, ClientConfig::new(transport), self.remote_addr)
        {
            self.association = Some((handle, assoc));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::sctp::PayloadProtocolIdentifier;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    #[test]
    fn a_server_that_hears_nothing_starts_the_association_itself() {
        let now = Instant::now();
        let mut server =
            SctpLayer::new(addr(40031), addr(40030), ResolvedRole::Server, 65536, now).unwrap();

        server.handle_timeout(now + Duration::from_secs(1));
        assert!(server.poll_transmit(now + Duration::from_secs(1)).is_none());

        let later = now + SERVER_INIT_FALLBACK + Duration::from_secs(1);
        server.handle_timeout(later);
        assert!(server.poll_transmit(later).is_some());
    }

    #[test]
    fn client_and_server_associate_and_exchange_a_message() {
        let mut now = Instant::now();

        let mut client =
            SctpLayer::new(addr(40020), addr(40021), ResolvedRole::Client, 65536, now).unwrap();
        let mut server =
            SctpLayer::new(addr(40021), addr(40020), ResolvedRole::Server, 65536, now).unwrap();

        let mut client_connected = false;
        let mut server_connected = false;

        for _ in 0..2000 {
            let mut progressed = false;

            while let Some(data) = client.poll_transmit(now) {
                progressed = true;
                server.handle_read(&data, now);
            }
            while let Some(data) = server.poll_transmit(now) {
                progressed = true;
                client.handle_read(&data, now);
            }

            while let Some(event) = client.poll_event() {
                progressed = true;
                if matches!(event, Event::Connected) {
                    client_connected = true;
                }
            }
            while let Some(event) = server.poll_event() {
                progressed = true;
                if matches!(event, Event::Connected) {
                    server_connected = true;
                }
            }

            if client_connected && server_connected {
                break;
            }

            if !progressed {
                let next = [client.poll_timeout(), server.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                now = next
                    .unwrap_or(now + Duration::from_millis(20))
                    .max(now + Duration::from_millis(1));
                client.handle_timeout(now);
                server.handle_timeout(now);
            }
        }

        assert!(client_connected, "client association never connected");
        assert!(server_connected, "server association never connected");

        {
            let assoc = client.association_mut().unwrap();
            let mut stream = assoc
                .open_stream(0, PayloadProtocolIdentifier::Binary)
                .unwrap();
            stream.write(now, b"hello over sctp").unwrap();
        }

        let mut delivered = None;
        for _ in 0..50 {
            let mut progressed = false;
            while let Some(data) = client.poll_transmit(now) {
                progressed = true;
                server.handle_read(&data, now);
            }
            while let Some(data) = server.poll_transmit(now) {
                progressed = true;
                client.handle_read(&data, now);
            }

            if let Some(assoc) = server.association_mut()
                && let Some(mut stream) = assoc.accept_stream()
                && let Ok(Some(chunks)) = stream.read()
            {
                delivered = Some(chunks.to_payload(65536).unwrap());
            }

            if delivered.is_some() {
                break;
            }
            if !progressed {
                now += Duration::from_millis(5);
                client.handle_timeout(now);
                server.handle_timeout(now);
            }
        }

        assert_eq!(delivered.as_deref(), Some(&b"hello over sctp"[..]));
    }
}

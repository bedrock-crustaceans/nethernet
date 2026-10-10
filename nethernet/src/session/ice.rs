use crate::error::ProtocolError;
use crate::protocol::webrtc::certificate;
use bytes::BytesMut;
use rtc::ice::agent::agent_config::AgentConfig;
use rtc::ice::agent::{Agent, Credentials, Event};
use rtc::ice::candidate::candidate_host::CandidateHostConfig;
use rtc::ice::candidate::{Candidate, CandidateConfig, CandidateType};
use rtc::ice::network_type::NetworkType;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct IceLayer {
    agent: Agent,
    local_addr: SocketAddr,
}

impl IceLayer {
    pub fn new(
        local_addr: SocketAddr,
        is_controlling: bool,
        now: Instant,
    ) -> Result<IceLayer, ProtocolError> {
        let config = AgentConfig {
            local_ufrag: rtc::ice::rand::generate_ufrag(),
            local_pwd: rtc::ice::rand::generate_pwd(),
            is_controlling,
            candidate_types: vec![CandidateType::Host],
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            ..Default::default()
        };

        let mut agent = Agent::new(now, Arc::new(config), certificate::crypto_provider()?)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: local_addr.ip().to_string(),
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        agent
            .add_local_candidate(candidate)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        Ok(Self { agent, local_addr })
    }

    pub fn local_credentials(&self) -> &Credentials {
        self.agent.get_local_credentials()
    }

    pub fn local_candidate(&self) -> &Candidate {
        &self.agent.get_local_candidates()[0]
    }

    pub fn set_remote_credentials(
        &mut self,
        ufrag: String,
        pwd: String,
    ) -> Result<(), ProtocolError> {
        self.agent
            .set_remote_credentials(ufrag, pwd)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<(), ProtocolError> {
        self.agent
            .add_remote_candidate(candidate)
            .map(|_| ())
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    pub fn handle_read(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<bool, ProtocolError> {
        if !is_stun_packet(data) {
            return Ok(false);
        }

        self.agent
            .handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr: from,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: BytesMut::from(data),
            })
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        Ok(true)
    }

    pub fn poll_write(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.agent
            .poll_write()
            .map(|msg| (msg.message.to_vec(), msg.transport.peer_addr))
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.agent.poll_event().map(|tagged| tagged.event)
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), ProtocolError> {
        self.agent
            .handle_timeout(now)
            .map_err(|e| ProtocolError::Other(format!("{e}")))
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.agent.poll_timeout()
    }

    pub fn selected_remote_addr(&self) -> Option<SocketAddr> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(_, remote)| remote.addr())
    }
}

fn is_stun_packet(data: &[u8]) -> bool {
    rtc::stun::message::is_stun_message(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::ice::state::ConnectionState;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    #[test]
    fn two_agents_connect_over_loopback() {
        let mut now = Instant::now();
        let mut a = IceLayer::new(addr(40000), true, now).unwrap();
        let mut b = IceLayer::new(addr(40001), false, now).unwrap();

        let a_creds = a.local_credentials().clone();
        let b_creds = b.local_credentials().clone();
        a.set_remote_credentials(b_creds.ufrag.clone(), b_creds.pwd.clone())
            .unwrap();
        b.set_remote_credentials(a_creds.ufrag.clone(), a_creds.pwd.clone())
            .unwrap();

        let a_candidate = a.local_candidate().clone();
        let b_candidate = b.local_candidate().clone();
        a.add_remote_candidate(b_candidate).unwrap();
        b.add_remote_candidate(a_candidate).unwrap();

        let mut a_connected = false;
        let mut b_connected = false;

        for _ in 0..2000 {
            let mut progressed = false;

            while let Some((data, to)) = a.poll_write() {
                progressed = true;
                assert_eq!(to, addr(40001));
                b.handle_read(&data, addr(40000), now).unwrap();
            }
            while let Some((data, to)) = b.poll_write() {
                progressed = true;
                assert_eq!(to, addr(40000));
                a.handle_read(&data, addr(40001), now).unwrap();
            }

            while let Some(event) = a.poll_event() {
                progressed = true;
                if let Event::ConnectionStateChange(ConnectionState::Connected) = event {
                    a_connected = true;
                }
            }
            while let Some(event) = b.poll_event() {
                progressed = true;
                if let Event::ConnectionStateChange(ConnectionState::Connected) = event {
                    b_connected = true;
                }
            }

            if a_connected && b_connected {
                break;
            }

            if !progressed {
                let next_timeout = [a.poll_timeout(), b.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                now = next_timeout
                    .unwrap_or(now + std::time::Duration::from_millis(20))
                    .max(now + std::time::Duration::from_millis(1));
                a.handle_timeout(now).unwrap();
                b.handle_timeout(now).unwrap();
            }
        }

        assert!(a_connected, "a never reached Connected");
        assert!(b_connected, "b never reached Connected");
        assert_eq!(a.selected_remote_addr(), Some(addr(40001)));
        assert_eq!(b.selected_remote_addr(), Some(addr(40000)));
    }

    #[test]
    fn stun_demux_rejects_non_stun_datagrams() {
        assert!(!is_stun_packet(&[22, 0, 0]));
        assert!(!is_stun_packet(&[23, 0, 0]));

        let mut stun_header = vec![0x00, 0x01, 0x00, 0x00];
        stun_header.extend_from_slice(&0x2112A442u32.to_be_bytes());
        stun_header.extend_from_slice(&[0u8; 12]);
        assert!(is_stun_packet(&stun_header));
    }
}

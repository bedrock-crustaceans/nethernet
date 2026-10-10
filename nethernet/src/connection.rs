use crate::error::ProtocolError;
use crate::protocol::webrtc::Description;
use crate::protocol::webrtc::candidate::{format_ice_candidate, parse_ice_candidate};
use crate::protocol::{Signal, SignalType};
use crate::sans::Sans;
use crate::session::{Channel, Session, SessionInput, SessionOutput};
use bytes::Bytes;
use rtc::ice::candidate::Candidate;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceMode {
    Full,
    Trickle,
}

enum SignalKind {
    Offer,
    Answer,
}

pub struct Connection {
    session: Session,
    connection_id: u64,
    remote_network_id: String,
    remote_identity: Option<String>,
}

impl Connection {
    pub fn connect(
        session: Session,
        description: Description,
        connection_id: u64,
        remote_network_id: String,
        ice_mode: IceMode,
    ) -> (Self, Vec<Signal>) {
        let signals = Self::describe(
            &session,
            &description,
            ice_mode,
            connection_id,
            remote_network_id.clone(),
            SignalKind::Offer,
        );

        (
            Self {
                session,
                connection_id,
                remote_network_id,
                remote_identity: None,
            },
            signals,
        )
    }

    pub fn parse_offer(offer: &Signal) -> Result<(Description, Vec<Candidate>), ProtocolError> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }
        Description::parse(&offer.data)
    }

    pub fn accept(
        mut session: Session,
        description: Description,
        offer: &Signal,
        remote_description: Description,
        remote_candidates: Vec<Candidate>,
        ice_mode: IceMode,
        now: Instant,
    ) -> Result<(Connection, Vec<Signal>), ProtocolError> {
        if offer.signal_type != SignalType::Offer {
            return Err(ProtocolError::Other("expected an offer signal".to_string()));
        }

        let remote_identity = remote_description.identity.clone();
        session.handle(SessionInput::RemoteDescription(
            remote_description,
            remote_candidates,
            now,
        ))?;

        let signals = Self::describe(
            &session,
            &description,
            ice_mode,
            offer.connection_id,
            offer.network_id.clone(),
            SignalKind::Answer,
        );

        Ok((
            Self {
                session,
                connection_id: offer.connection_id,
                remote_network_id: offer.network_id.clone(),
                remote_identity,
            },
            signals,
        ))
    }

    fn describe(
        session: &Session,
        description: &Description,
        ice_mode: IceMode,
        connection_id: u64,
        remote_network_id: String,
        kind: SignalKind,
    ) -> Vec<Signal> {
        let sdp = match ice_mode {
            IceMode::Full => description.encode_full(&[session.local_candidate().clone()]),
            IceMode::Trickle => description.encode_trickle(),
        };

        let mut signals = vec![match kind {
            SignalKind::Offer => Signal::offer(connection_id, sdp, remote_network_id.clone()),
            SignalKind::Answer => Signal::answer(connection_id, sdp, remote_network_id.clone()),
        }];

        if ice_mode == IceMode::Trickle {
            signals.push(Signal::candidate(
                connection_id,
                format_ice_candidate(0, session.local_candidate(), &description.ice.ufrag),
                remote_network_id,
            ));
        }

        signals
    }

    fn handle_signal(&mut self, signal: &Signal, now: Instant) -> Result<(), ProtocolError> {
        if signal.connection_id != self.connection_id || signal.network_id != self.remote_network_id
        {
            return Ok(());
        }

        match signal.signal_type {
            SignalType::Answer => {
                let (description, candidates) = Description::parse(&signal.data)?;
                self.remote_identity = description.identity.clone();
                self.session.handle(SessionInput::RemoteDescription(
                    description,
                    candidates,
                    now,
                ))?;
            }
            SignalType::Candidate => {
                let candidate = parse_ice_candidate(&signal.data)?;
                self.session
                    .handle(SessionInput::RemoteCandidate(candidate, now))?;
            }
            SignalType::Error => {
                return Err(ProtocolError::Other(format!(
                    "remote signaled a connection error: {}",
                    signal.data
                )));
            }
            SignalType::Offer => {}
        }

        Ok(())
    }

    pub fn remote_identity(&self) -> Option<&str> {
        self.remote_identity.as_deref()
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.session.remote_addr()
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.session.rtt()
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }
}

pub enum ConnectionInput {
    Packet(Box<[u8]>, SocketAddr, Instant),

    Timeout(Instant),

    Signal(Signal, Instant),

    Send(Channel, Bytes, Instant),
}

impl Sans for Connection {
    type Input = ConnectionInput;
    type Output = SessionOutput;
    type Error = ProtocolError;

    fn handle(&mut self, msg: ConnectionInput) -> Result<(), ProtocolError> {
        match msg {
            ConnectionInput::Packet(data, from, now) => {
                self.session.handle(SessionInput::Packet(data, from, now))
            }
            ConnectionInput::Timeout(now) => self.session.handle(SessionInput::Timeout(now)),
            ConnectionInput::Signal(signal, now) => self.handle_signal(&signal, now),
            ConnectionInput::Send(channel, data, now) => {
                self.session.handle(SessionInput::Send(channel, data, now))
            }
        }
    }

    fn poll(&mut self) -> Option<SessionOutput> {
        self.session.poll()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub negotiation: Duration,

    pub start: Duration,

    pub channel: Duration,
}

impl Timeouts {
    pub fn establish(&self) -> Duration {
        self.start + self.channel
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            negotiation: Duration::from_secs(15),
            start: Duration::from_secs(5),
            channel: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::webrtc::identity;
    use crate::session::SessionEvent;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn default_timeouts_establish_within_ten_seconds() {
        assert_eq!(Timeouts::default().establish(), Duration::from_secs(10));
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    fn assert_connects(ice_mode: IceMode) {
        let mut now = Instant::now();

        let (offer_session, offer_description) = Session::new(addr(40200), true, now).unwrap();
        let (mut offerer, offer_signals) = Connection::connect(
            offer_session,
            offer_description,
            42,
            7.to_string(),
            ice_mode,
        );
        let mut offer_iter = offer_signals.into_iter();
        let offer = offer_iter.next().unwrap();
        assert_eq!(offer.signal_type, SignalType::Offer);

        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        let (answer_session, answer_description) = Session::new(addr(40201), false, now).unwrap();
        let (mut answerer, answer_signals) = Connection::accept(
            answer_session,
            answer_description,
            &offer,
            remote_description,
            remote_candidates,
            ice_mode,
            now,
        )
        .unwrap();
        let mut answer_iter = answer_signals.into_iter();
        let answer = answer_iter.next().unwrap();
        assert_eq!(answer.signal_type, SignalType::Answer);

        offerer
            .handle(ConnectionInput::Signal(answer, now))
            .unwrap();

        for signal in offer_iter {
            answerer
                .handle(ConnectionInput::Signal(signal, now))
                .unwrap();
        }
        for signal in answer_iter {
            offerer
                .handle(ConnectionInput::Signal(signal, now))
                .unwrap();
        }

        let mut offerer_ready = false;
        let mut answerer_ready = false;

        for _ in 0..5000 {
            let mut progressed = false;

            let mut outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => offerer_ready = true,
                    SessionOutput::Event(SessionEvent::Failed) => {
                        panic!("session failed unexpectedly")
                    }
                    SessionOutput::Message(..) => {}
                    SessionOutput::Wait(_) => {}
                }
            }
            for (data, to) in outbox {
                answerer
                    .handle(ConnectionInput::Packet(data.into(), to, now))
                    .unwrap();
            }

            let mut outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => answerer_ready = true,
                    SessionOutput::Event(SessionEvent::Failed) => {
                        panic!("session failed unexpectedly")
                    }
                    SessionOutput::Message(..) => {}
                    SessionOutput::Wait(_) => {}
                }
            }
            for (data, to) in outbox {
                offerer
                    .handle(ConnectionInput::Packet(data.into(), to, now))
                    .unwrap();
            }

            if offerer_ready && answerer_ready {
                break;
            }

            if !progressed {
                now += Duration::from_millis(5);
                offerer.handle(ConnectionInput::Timeout(now)).unwrap();
                answerer.handle(ConnectionInput::Timeout(now)).unwrap();
            }
        }

        assert!(offerer_ready, "offerer never became ready ({ice_mode:?})");
        assert!(answerer_ready, "answerer never became ready ({ice_mode:?})");
    }

    #[test]
    fn connects_with_full_ice() {
        assert_connects(IceMode::Full);
    }

    #[test]
    fn connects_with_trickle_ice() {
        assert_connects(IceMode::Trickle);
    }

    #[test]
    fn signals_for_a_different_connection_are_ignored() {
        let now = Instant::now();
        let (session, description) = Session::new(addr(40210), true, now).unwrap();
        let (mut offerer, _) =
            Connection::connect(session, description, 1, 7.to_string(), IceMode::Full);
        let unrelated = Signal::answer(999, "irrelevant".to_string(), "7".to_string());
        offerer
            .handle(ConnectionInput::Signal(unrelated, now))
            .unwrap();
    }

    fn decode_cpk(claims: &serde_json::Value) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims["cpk"].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn identity_assertions_flow_and_verify_in_both_directions() {
        let now = Instant::now();
        let (offerer_keypair, _) = identity::generate_keypair().unwrap();
        let (answerer_keypair, _) = identity::generate_keypair().unwrap();

        let (offer_session, mut offer_description) = Session::new(addr(40220), true, now).unwrap();
        let offerer_token =
            identity::build_server_token(&offerer_keypair, serde_json::Map::new(), None).unwrap();
        offer_description.identity = Some(
            identity::build_identity(
                "offerer.example",
                &offerer_token,
                &[offer_description.fingerprint.clone()],
                &offerer_keypair,
            )
            .unwrap(),
        );

        let (mut offerer, offer_signals) = Connection::connect(
            offer_session,
            offer_description,
            1,
            7.to_string(),
            IceMode::Full,
        );
        let offer = offer_signals.into_iter().next().unwrap();

        let (remote_description, remote_candidates) = Connection::parse_offer(&offer).unwrap();
        let parsed =
            identity::parse_identity(remote_description.identity.as_ref().unwrap()).unwrap();
        assert_eq!(parsed.idp.domain, "offerer.example");
        let offerer_decoded = identity::verify_self_signed(&parsed.token).unwrap();
        parsed
            .verify_fingerprints(
                &decode_cpk(&offerer_decoded.claims),
                std::slice::from_ref(&remote_description.fingerprint),
            )
            .unwrap();

        let (answer_session, mut answer_description) =
            Session::new(addr(40221), false, now).unwrap();
        let answerer_token =
            identity::build_server_token(&answerer_keypair, serde_json::Map::new(), None).unwrap();
        answer_description.identity = Some(
            identity::build_identity(
                "answerer.example",
                &answerer_token,
                &[answer_description.fingerprint.clone()],
                &answerer_keypair,
            )
            .unwrap(),
        );

        let (_answerer, answer_signals) = Connection::accept(
            answer_session,
            answer_description,
            &offer,
            remote_description,
            remote_candidates,
            IceMode::Full,
            now,
        )
        .unwrap();
        let answer = answer_signals.into_iter().next().unwrap();

        offerer
            .handle(ConnectionInput::Signal(answer.clone(), now))
            .unwrap();

        let (answer_description, _) = Description::parse(&answer.data).unwrap();
        let parsed = identity::parse_identity(offerer.remote_identity().unwrap()).unwrap();
        assert_eq!(parsed.idp.domain, "answerer.example");
        let answerer_decoded = identity::verify_self_signed(&parsed.token).unwrap();
        parsed
            .verify_fingerprints(
                &decode_cpk(&answerer_decoded.claims),
                &[answer_description.fingerprint],
            )
            .unwrap();
    }
}

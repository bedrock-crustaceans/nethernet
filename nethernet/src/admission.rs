use crate::connection::{Connection, ConnectionInput, IceMode};
use crate::error::{ProtocolError, SignalErrorCode};
use crate::identity::error::IdentityError;
use crate::identity::{PlayerInfo, ServerIdentity, TokenTrust, validate_sdp};
use crate::protocol::Signal;
use crate::protocol::webrtc::Description;
use crate::sans::Sans;
use crate::session::Session;
use crate::util::candidate;
use rtc::ice::candidate::Candidate;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("offer description rejected: {0}")]
    Description(ProtocolError),

    #[error("offer identity rejected: {0}")]
    Untrusted(IdentityError),

    #[error("session creation failed: {0}")]
    Session(ProtocolError),

    #[error("answer creation failed: {0}")]
    Answer(ProtocolError),

    #[error("answer signing failed: {0}")]
    Signing(IdentityError),
}

impl AdmissionError {
    pub fn code(&self) -> SignalErrorCode {
        match self {
            Self::Description(_) => SignalErrorCode::FailedToSetRemoteDescription,
            Self::Untrusted(_) => SignalErrorCode::NotLoggedIn,
            Self::Session(_) => SignalErrorCode::FailedToCreatePeerConnection,
            Self::Answer(_) | Self::Signing(_) => SignalErrorCode::FailedToCreateAnswer,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OfferPolicy<'a> {
    identity: Option<&'a ServerIdentity>,
    token_trust: Option<&'a TokenTrust>,
    infer_peer_candidates: bool,
    ice_mode: IceMode,
}

impl<'a> OfferPolicy<'a> {
    pub fn new(ice_mode: IceMode) -> Self {
        Self {
            identity: None,
            token_trust: None,
            infer_peer_candidates: false,
            ice_mode,
        }
    }

    pub fn with_identity(mut self, identity: &'a ServerIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_token_trust(mut self, trust: &'a TokenTrust) -> Self {
        self.token_trust = Some(trust);
        self
    }

    pub fn with_inferred_peer_candidates(mut self, infer: bool) -> Self {
        self.infer_peer_candidates = infer;
        self
    }

    pub fn admit(
        &self,
        offer: &Signal,
        signaled_from: Option<SocketAddr>,
        wall: SystemTime,
    ) -> Result<Admitted<'a>, AdmissionError> {
        let (remote_description, remote_candidates) =
            Connection::parse_offer(offer).map_err(AdmissionError::Description)?;
        let player = match self.token_trust {
            Some(trust) => {
                let claims =
                    validate_sdp(&offer.data, trust, wall).map_err(AdmissionError::Untrusted)?;
                Some(PlayerInfo::new(
                    claims,
                    offer.network_id.clone(),
                    signaled_from,
                ))
            }
            None => None,
        };
        Ok(Admitted {
            policy: *self,
            offer: offer.clone(),
            signaled_from,
            remote_description,
            remote_candidates,
            player,
        })
    }
}

pub struct Admitted<'a> {
    policy: OfferPolicy<'a>,
    offer: Signal,
    signaled_from: Option<SocketAddr>,
    remote_description: Description,
    remote_candidates: Vec<Candidate>,
    player: Option<PlayerInfo>,
}

impl Admitted<'_> {
    pub fn player(&self) -> Option<&PlayerInfo> {
        self.player.as_ref()
    }

    pub fn answer(self, local_addr: SocketAddr, now: Instant) -> Result<Answered, AdmissionError> {
        let (session, description) =
            Session::new(local_addr, false, now).map_err(AdmissionError::Session)?;
        let local_ufrag = description.ice.ufrag.clone();
        let (mut connection, mut signals) = Connection::accept(
            session,
            description,
            &self.offer,
            self.remote_description,
            self.remote_candidates,
            self.policy.ice_mode,
            now,
        )
        .map_err(AdmissionError::Answer)?;

        if let (Some(identity), Some(answer)) = (self.policy.identity, signals.first_mut()) {
            answer.data = identity
                .augment(&answer.data)
                .map_err(AdmissionError::Signing)?;
        }

        let mut inferred = Vec::new();
        if self.policy.infer_peer_candidates
            && !candidate::has_routable_host_candidate(&self.offer.data)
        {
            for line in candidate::inferred_peer_candidates(&self.offer.data, self.signaled_from) {
                let signal = Signal::candidate(
                    self.offer.connection_id,
                    line.clone(),
                    self.offer.network_id.clone(),
                );
                if connection
                    .handle(ConnectionInput::Signal(signal, now))
                    .is_ok()
                {
                    inferred.push(line);
                }
            }
        }

        Ok(Answered {
            connection,
            signals,
            player: self.player,
            local_ufrag,
            inferred,
        })
    }
}

pub struct Answered {
    pub connection: Connection,

    pub signals: Vec<Signal>,

    pub player: Option<PlayerInfo>,

    pub local_ufrag: String,

    pub inferred: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SignalType;
    use std::net::{Ipv4Addr, SocketAddr};

    const CONNECTION_ID: u64 = 42;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    fn public_peer() -> SocketAddr {
        "93.184.216.34:19132".parse().unwrap()
    }

    fn loopback_offer() -> Signal {
        let (session, description) = Session::new(loopback(40300), true, Instant::now()).unwrap();
        let (_, signals) = Connection::connect(
            session,
            description,
            CONNECTION_ID,
            "peer".to_string(),
            IceMode::Full,
        );
        signals.into_iter().next().unwrap()
    }

    fn test_identity() -> ServerIdentity {
        ServerIdentity::generate("example.test", SystemTime::now()).unwrap()
    }

    #[test]
    fn an_answer_carries_a_valid_identity() {
        let identity = test_identity();
        let policy = OfferPolicy::new(IceMode::Full).with_identity(&identity);
        let answered = policy
            .admit(&loopback_offer(), None, SystemTime::now())
            .unwrap()
            .answer(loopback(40301), Instant::now())
            .unwrap();
        let answer = &answered.signals[0];
        assert_eq!(answer.signal_type, SignalType::Answer);
        assert!(validate_sdp(&answer.data, &TokenTrust::Any, SystemTime::now()).is_ok());
    }

    #[test]
    fn an_unsigned_offer_is_not_logged_in() {
        let policy = OfferPolicy::new(IceMode::Full).with_token_trust(&TokenTrust::Any);
        let error = policy
            .admit(&loopback_offer(), None, SystemTime::now())
            .err()
            .expect("an unsigned offer must be rejected");
        assert_eq!(error.code(), SignalErrorCode::NotLoggedIn);
    }

    #[test]
    fn candidates_are_inferred_for_a_loopback_offer() {
        let policy = OfferPolicy::new(IceMode::Full).with_inferred_peer_candidates(true);
        let answered = policy
            .admit(&loopback_offer(), Some(public_peer()), SystemTime::now())
            .unwrap()
            .answer(loopback(40302), Instant::now())
            .unwrap();
        assert!(
            answered
                .inferred
                .iter()
                .all(|line| line.contains("93.184.216.34")),
            "inferred candidates must name the signaled address"
        );
        assert!(!answered.inferred.is_empty(), "nothing was inferred");
    }

    #[test]
    fn nothing_is_inferred_when_disabled() {
        let policy = OfferPolicy::new(IceMode::Full).with_inferred_peer_candidates(false);
        let answered = policy
            .admit(&loopback_offer(), Some(public_peer()), SystemTime::now())
            .unwrap()
            .answer(loopback(40303), Instant::now())
            .unwrap();
        assert!(answered.inferred.is_empty());
    }
}

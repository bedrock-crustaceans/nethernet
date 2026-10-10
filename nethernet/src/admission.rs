//! The decision to admit an offer, answer it, sign the answer and infer candidates for the
//! peer, shared by every driver so that each one treats an offer the same way.

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

/// Why an offer was not admitted or could not be answered.
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// The offer is not a description that can be negotiated against.
    #[error("offer description rejected: {0}")]
    Description(ProtocolError),

    /// The peer did not prove an identity the policy trusts.
    #[error("offer identity rejected: {0}")]
    Untrusted(IdentityError),

    /// The local session could not be created.
    #[error("session creation failed: {0}")]
    Session(ProtocolError),

    /// The answer could not be produced.
    #[error("answer creation failed: {0}")]
    Answer(ProtocolError),

    /// The answer could not be signed with the server identity.
    #[error("answer signing failed: {0}")]
    Signing(IdentityError),
}

impl AdmissionError {
    /// The code to signal back to the peer that sent the offer.
    pub fn code(&self) -> SignalErrorCode {
        match self {
            Self::Description(_) => SignalErrorCode::FailedToSetRemoteDescription,
            Self::Untrusted(_) => SignalErrorCode::NotLoggedIn,
            Self::Session(_) => SignalErrorCode::FailedToCreatePeerConnection,
            Self::Answer(_) | Self::Signing(_) => SignalErrorCode::FailedToCreateAnswer,
        }
    }
}

/// How a server treats the offers it receives.
#[derive(Debug, Clone, Copy)]
pub struct OfferPolicy<'a> {
    identity: Option<&'a ServerIdentity>,
    token_trust: Option<&'a TokenTrust>,
    infer_peer_candidates: bool,
    ice_mode: IceMode,
}

impl<'a> OfferPolicy<'a> {
    /// A policy that accepts any offer, signs nothing and infers nothing.
    pub fn new(ice_mode: IceMode) -> Self {
        Self {
            identity: None,
            token_trust: None,
            infer_peer_candidates: false,
            ice_mode,
        }
    }

    /// Signs every answer with the identity, so that clients can pin its key.
    pub fn with_identity(mut self, identity: &'a ServerIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Requires every offer to carry an identity the trust accepts.
    pub fn with_token_trust(mut self, trust: &'a TokenTrust) -> Self {
        self.token_trust = Some(trust);
        self
    }

    /// Whether to add candidates for the address a peer signaled from when it offers no
    /// routable one.
    pub fn with_inferred_peer_candidates(mut self, infer: bool) -> Self {
        self.infer_peer_candidates = infer;
        self
    }

    /// Parses the offer and validates the identity it carries when the policy asks for
    /// one, without creating any session.
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

/// An offer that passed the policy and is waiting for a local address to answer from.
pub struct Admitted<'a> {
    policy: OfferPolicy<'a>,
    offer: Signal,
    signaled_from: Option<SocketAddr>,
    remote_description: Description,
    remote_candidates: Vec<Candidate>,
    player: Option<PlayerInfo>,
}

impl Admitted<'_> {
    /// The validated identity of the peer, or [`None`] when the policy asks for none.
    pub fn player(&self) -> Option<&PlayerInfo> {
        self.player.as_ref()
    }

    /// Creates the session on `local_addr` and answers the offer.
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

/// An answered offer: the connection and what to signal back to the peer.
pub struct Answered {
    /// The connection, with any inferred candidates already applied.
    pub connection: Connection,

    /// The answer, signed when the policy has an identity, followed by any trickled
    /// candidates.
    pub signals: Vec<Signal>,

    /// The validated identity of the peer, or [`None`] when the policy asks for none.
    pub player: Option<PlayerInfo>,

    /// The ICE username fragment of the local side, which demultiplexes shared sockets.
    pub local_ufrag: String,

    /// The candidates inferred for the peer, in the form signaled over the wire.
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

//! A DTLS-secured SCTP session over ICE with the two NetherNet data channels.
mod dcep;
mod dtls;
mod ice;
mod sctp;

use crate::error::ProtocolError;
use crate::protocol::constants::SCTP_MAX_MESSAGE_SIZE;
use crate::protocol::message::{Message as Framing, MessageSegment};
use crate::protocol::webrtc::{Description, DtlsRole, certificate};
use crate::sans::Sans;
use dtls::EndpointEvent;
pub use dtls::ResolvedRole;
use ice::IceLayer;
use rtc::datachannel::message::Message as DcepMessage;
use rtc::ice::candidate::Candidate;
use rtc::ice::state::ConnectionState as IceConnectionState;
use rtc::sctp::{Event as SctpEvent, PayloadProtocolIdentifier, StreamId};
use sctp::SctpLayer;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const RELIABLE_STREAM_ID: StreamId = 1;
const UNRELIABLE_STREAM_ID: StreamId = 3;

/// Reliable messages are segmented; unreliable ones must fit one segment (guide section 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Reliable,
    Unreliable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Both data channels are open.
    Ready,
    /// ICE or SCTP failed; emitted once.
    Failed,
}

pub enum SessionOutput {
    Send(Vec<u8>, SocketAddr),
    Event(SessionEvent),
    Message(Channel, Vec<u8>),
    /// Feed `Timeout` no later than this long from now.
    Wait(Duration),
}

pub enum SessionInput {
    Packet(Box<[u8]>, SocketAddr, Instant),

    /// Transports start once the description or a later candidate supplies a remote address.
    RemoteDescription(Description, Vec<Candidate>, Instant),

    RemoteCandidate(Candidate, Instant),

    /// Fails until the channel has opened.
    Send(Channel, bytes::Bytes, Instant),

    Timeout(Instant),
}

struct RemoteInfo {
    addr: SocketAddr,
}

#[derive(Default)]
struct Channels {
    reliable_stream_id: Option<StreamId>,
    unreliable_stream_id: Option<StreamId>,
    reassembly: Framing,
    ready_emitted: bool,
    failed_emitted: bool,
}

impl Channels {
    fn stream_id(&self, channel: Channel) -> Option<StreamId> {
        match channel {
            Channel::Reliable => self.reliable_stream_id,
            Channel::Unreliable => self.unreliable_stream_id,
        }
    }

    fn set_open(&mut self, channel: Channel, stream_id: StreamId) {
        match channel {
            Channel::Reliable => self.reliable_stream_id = Some(stream_id),
            Channel::Unreliable => self.unreliable_stream_id = Some(stream_id),
        }
    }
}

/// ICE, DTLS and SCTP stacks bound to one local address, with one reliable and one unreliable channel.
pub struct Session {
    is_controlling: bool,
    local_addr: SocketAddr,
    local_description: Description,
    ice: IceLayer,
    certificate: Option<rtc::dtls::crypto::Certificate>,

    pending_role_fingerprint: Option<(ResolvedRole, (String, String))>,

    remote: Option<RemoteInfo>,
    dtls: Option<DtlsLayer>,
    sctp: Option<SctpLayer>,

    channels: Channels,
    output: VecDeque<SessionOutput>,
}

pub use dtls::DtlsLayer;

impl Session {
    /// The controlling side is the offerer: it announces the DTLS server role and opens the data channels.
    pub fn new(
        local_addr: SocketAddr,
        is_controlling: bool,
        now: Instant,
    ) -> Result<(Session, Description), ProtocolError> {
        let ice = IceLayer::new(local_addr, is_controlling, now)?;
        let certificate = certificate::generate()?;
        let fingerprint = certificate::fingerprint(&certificate)?;

        let local_description = Description {
            ice: ice.local_credentials().clone(),
            dtls_role: if is_controlling {
                DtlsRole::Server
            } else {
                DtlsRole::Auto
            },
            fingerprint,
            sctp_max_message_size: SCTP_MAX_MESSAGE_SIZE,
            identity: None,
        };

        let session = Self {
            is_controlling,
            local_addr,
            local_description: local_description.clone(),
            ice,
            certificate: Some(certificate),
            pending_role_fingerprint: None,
            remote: None,
            dtls: None,
            sctp: None,
            channels: Channels::default(),
            output: VecDeque::new(),
        };

        Ok((session, local_description))
    }

    pub fn local_candidate(&self) -> &Candidate {
        self.ice.local_candidate()
    }

    /// The selected ICE remote address, else the first candidate's.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.ice
            .selected_remote_addr()
            .or_else(|| self.remote.as_ref().map(|r| r.addr))
    }

    /// Available once the SCTP association exists.
    pub fn rtt(&self) -> Option<Duration> {
        self.sctp.as_ref().and_then(|s| s.rtt())
    }

    fn set_remote_description(
        &mut self,
        remote: &Description,
        candidates: Vec<Candidate>,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.ice
            .set_remote_credentials(remote.ice.ufrag.clone(), remote.ice.pwd.clone())?;

        let resolved_role = ResolvedRole::from_remote_announced(remote.dtls_role);
        let fingerprint = remote.fingerprint.clone();

        for candidate in &candidates {
            self.ice.add_remote_candidate(candidate.clone())?;
        }

        if let Some(candidate) = candidates.into_iter().next() {
            self.start_transports(candidate.addr(), resolved_role, fingerprint, now)?;
        } else {
            self.pending_role_fingerprint = Some((resolved_role, fingerprint));
        }

        Ok(())
    }

    fn add_remote_candidate(
        &mut self,
        candidate: Candidate,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let addr = candidate.addr();
        self.ice.add_remote_candidate(candidate)?;

        if self.remote.is_none()
            && let Some((resolved_role, fingerprint)) = self.pending_role_fingerprint.take()
        {
            self.start_transports(addr, resolved_role, fingerprint, now)?;
        }

        Ok(())
    }

    fn start_transports(
        &mut self,
        remote_addr: SocketAddr,
        resolved_role: ResolvedRole,
        remote_fingerprint: (String, String),
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let certificate = self
            .certificate
            .take()
            .ok_or_else(|| ProtocolError::Other("transports already started".to_string()))?;
        let dtls = DtlsLayer::new(
            self.local_addr,
            remote_addr,
            resolved_role,
            certificate,
            remote_fingerprint,
            now,
        )?;
        let sctp = SctpLayer::new(
            self.local_addr,
            remote_addr,
            resolved_role,
            self.local_description.sctp_max_message_size,
            now,
        )?;

        self.remote = Some(RemoteInfo { addr: remote_addr });
        self.dtls = Some(dtls);
        self.sctp = Some(sctp);

        Ok(())
    }

    fn handle_packet(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        if self.ice.handle_read(data, from, now)? {
            self.pump(now)?;
            return Ok(());
        }

        if let Some(dtls) = &mut self.dtls {
            let events = dtls.handle_read(data, now)?;
            for event in events {
                self.handle_dtls_event(event, now);
            }
        }

        self.pump(now)?;
        Ok(())
    }

    fn handle_dtls_event(&mut self, event: EndpointEvent, now: Instant) {
        if let EndpointEvent::ApplicationData(data) = event
            && let Some(sctp) = &mut self.sctp
        {
            sctp.handle_read(&data, now);
        }
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), ProtocolError> {
        self.ice.handle_timeout(now)?;
        if let Some(dtls) = &mut self.dtls {
            dtls.handle_timeout(now)?;
        }
        if let Some(sctp) = &mut self.sctp {
            sctp.handle_timeout(now);
        }
        self.pump(now)?;

        if let Some(deadline) = self.poll_timeout() {
            self.output
                .push_back(SessionOutput::Wait(deadline.saturating_duration_since(now)));
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        [
            self.ice.poll_timeout(),
            self.dtls.as_ref().and_then(|d| d.poll_timeout()),
            self.sctp.as_ref().and_then(|s| s.poll_timeout()),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn send(
        &mut self,
        channel: Channel,
        data: bytes::Bytes,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        let stream_id = self
            .channels
            .stream_id(channel)
            .ok_or_else(|| ProtocolError::Other("channel not open yet".to_string()))?;

        let sctp = self
            .sctp
            .as_mut()
            .ok_or_else(|| ProtocolError::Other("transports not started".to_string()))?;
        let assoc = sctp
            .association_mut()
            .ok_or_else(|| ProtocolError::Other("association not established".to_string()))?;
        let mut stream = assoc
            .stream(stream_id)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;

        match channel {
            Channel::Reliable => {
                for segment in Framing::split_into_segments(data)? {
                    stream
                        .write_with_ppi(now, &segment.encode(), PayloadProtocolIdentifier::Binary)
                        .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                }
            }
            Channel::Unreliable => {
                let encoded = Framing::encode_unreliable(data)?;
                stream
                    .write_with_ppi(now, &encoded, PayloadProtocolIdentifier::Binary)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
            }
        }

        Ok(())
    }

    fn pump(&mut self, now: Instant) -> Result<(), ProtocolError> {
        while let Some((data, to)) = self.ice.poll_write() {
            self.output.push_back(SessionOutput::Send(data, to));
        }
        while let Some(event) = self.ice.poll_event() {
            if let rtc::ice::agent::Event::ConnectionStateChange(state) = event
                && matches!(
                    state,
                    IceConnectionState::Failed
                        | IceConnectionState::Disconnected
                        | IceConnectionState::Closed
                )
            {
                self.fail();
            }
        }

        let mut failed = false;
        if let (Some(sctp), Some(dtls)) = (&mut self.sctp, &mut self.dtls) {
            while let Some(event) = sctp.poll_event() {
                match event {
                    SctpEvent::Connected => open_channels_if_controlling(
                        self.is_controlling,
                        sctp,
                        &mut self.channels,
                        now,
                    )?,
                    SctpEvent::HandshakeFailed { .. } | SctpEvent::AssociationLost { .. } => {
                        failed = true;
                    }
                    _ => {}
                }
            }

            drain_dcep_and_data(sctp, &mut self.channels, &mut self.output, now)?;

            while let Some(packet) = sctp.poll_transmit(now) {
                dtls.write(&packet, now)?;
            }

            while let Some((data, to)) = dtls.poll_transmit() {
                self.output.push_back(SessionOutput::Send(data, to));
            }
        }
        if failed {
            self.fail();
        }

        if self.channels.reliable_stream_id.is_some()
            && self.channels.unreliable_stream_id.is_some()
            && !self.channels.ready_emitted
        {
            self.channels.ready_emitted = true;
            self.output
                .push_back(SessionOutput::Event(SessionEvent::Ready));
        }

        Ok(())
    }

    fn fail(&mut self) {
        if !self.channels.failed_emitted {
            self.channels.failed_emitted = true;
            self.output
                .push_back(SessionOutput::Event(SessionEvent::Failed));
        }
    }
}

impl Sans for Session {
    type Input = SessionInput;
    type Output = SessionOutput;
    type Error = ProtocolError;

    fn handle(&mut self, msg: SessionInput) -> Result<(), ProtocolError> {
        match msg {
            SessionInput::Packet(data, from, now) => self.handle_packet(&data, from, now),
            SessionInput::RemoteDescription(remote, candidates, now) => {
                self.set_remote_description(&remote, candidates, now)
            }
            SessionInput::RemoteCandidate(candidate, now) => {
                self.add_remote_candidate(candidate, now)
            }
            SessionInput::Send(channel, data, now) => self.send(channel, data, now),
            SessionInput::Timeout(now) => self.handle_timeout(now),
        }
    }

    fn poll(&mut self) -> Option<SessionOutput> {
        self.output.pop_front()
    }
}

fn open_channels_if_controlling(
    is_controlling: bool,
    sctp: &mut SctpLayer,
    channels: &mut Channels,
    now: Instant,
) -> Result<(), ProtocolError> {
    if !is_controlling {
        return Ok(());
    }
    let Some(assoc) = sctp.association_mut() else {
        return Ok(());
    };

    for (stream_id, channel, open) in [
        (RELIABLE_STREAM_ID, Channel::Reliable, dcep::reliable_open()),
        (
            UNRELIABLE_STREAM_ID,
            Channel::Unreliable,
            dcep::unreliable_open(),
        ),
    ] {
        let mut stream = assoc
            .open_stream(stream_id, PayloadProtocolIdentifier::Binary)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;
        let encoded = dcep::encode_open(open)?;
        stream
            .write_with_ppi(now, &encoded, dcep::PPI_DCEP)
            .map_err(|e| ProtocolError::Other(format!("{e}")))?;
        channels.set_open(channel, stream_id);
    }

    Ok(())
}

fn drain_dcep_and_data(
    sctp: &mut SctpLayer,
    channels: &mut Channels,
    output: &mut VecDeque<SessionOutput>,
    now: Instant,
) -> Result<(), ProtocolError> {
    let Some(assoc) = sctp.association_mut() else {
        return Ok(());
    };

    while let Some(mut stream) = assoc.accept_stream() {
        if let Ok(Some(chunks)) = stream.read()
            && let Ok(data) = chunks.to_payload(4096)
            && let Ok(DcepMessage::DataChannelOpen(open)) = dcep::decode(&data)
        {
            let channel = if open.label == dcep::RELIABLE_CHANNEL_LABEL.as_bytes() {
                Some(Channel::Reliable)
            } else if open.label == dcep::UNRELIABLE_CHANNEL_LABEL.as_bytes() {
                Some(Channel::Unreliable)
            } else {
                None
            };
            if let Some(channel) = channel {
                let stream_id = stream.stream_identifier();
                let ack = dcep::encode_ack()?;
                stream
                    .write_with_ppi(now, &ack, dcep::PPI_DCEP)
                    .map_err(|e| ProtocolError::Other(format!("{e}")))?;
                channels.set_open(channel, stream_id);
            }
        }
    }

    for channel in [Channel::Reliable, Channel::Unreliable] {
        let Some(stream_id) = channels.stream_id(channel) else {
            continue;
        };
        let Ok(mut stream) = assoc.stream(stream_id) else {
            continue;
        };
        while let Ok(Some(chunks)) = stream.read() {
            let is_dcep = matches!(chunks.ppi, PayloadProtocolIdentifier::Dcep);
            let Ok(data) = chunks.to_payload(1 << 20) else {
                continue;
            };

            if is_dcep {
                continue;
            }

            let Ok(segment) = MessageSegment::decode(data.freeze()) else {
                continue;
            };

            match channel {
                Channel::Reliable => match channels.reassembly.add_segment(segment) {
                    Ok(Some(message)) => output
                        .push_back(SessionOutput::Message(Channel::Reliable, message.to_vec())),
                    Ok(None) => {}
                    Err(e) => tracing::debug!("dropping malformed reliable segment: {e}"),
                },
                Channel::Unreliable => {
                    if segment.remaining_segments == 0 {
                        output.push_back(SessionOutput::Message(
                            Channel::Unreliable,
                            segment.data.to_vec(),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    #[test]
    fn full_handshake_and_bidirectional_data_exchange() {
        let mut now = Instant::now();

        let (mut offerer, offer) = Session::new(addr(40100), true, now).unwrap();
        let (mut answerer, answer) = Session::new(addr(40101), false, now).unwrap();

        let offer_sdp = offer.encode_full(&[offerer.local_candidate().clone()]);
        let answer_sdp = answer.encode_full(&[answerer.local_candidate().clone()]);

        let (parsed_offer, offer_candidates) = Description::parse(&offer_sdp).unwrap();
        let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();

        answerer
            .handle(SessionInput::RemoteDescription(
                parsed_offer,
                offer_candidates,
                now,
            ))
            .unwrap();
        offerer
            .handle(SessionInput::RemoteDescription(
                parsed_answer,
                answer_candidates,
                now,
            ))
            .unwrap();

        let mut offerer_ready = false;
        let mut answerer_ready = false;

        for _ in 0..5000 {
            let mut progressed = false;

            let mut offerer_outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => offerer_outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => offerer_ready = true,
                    SessionOutput::Event(SessionEvent::Failed) => {
                        panic!("session failed unexpectedly")
                    }
                    SessionOutput::Message(..) => panic!("unexpected message before Ready"),
                    SessionOutput::Wait(_) => {}
                }
            }
            for (data, to) in offerer_outbox {
                assert_eq!(to, addr(40101));
                answerer
                    .handle(SessionInput::Packet(data.into(), addr(40100), now))
                    .unwrap();
            }

            let mut answerer_outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => answerer_outbox.push((data, to)),
                    SessionOutput::Event(SessionEvent::Ready) => answerer_ready = true,
                    SessionOutput::Event(SessionEvent::Failed) => {
                        panic!("session failed unexpectedly")
                    }
                    SessionOutput::Message(..) => panic!("unexpected message before Ready"),
                    SessionOutput::Wait(_) => {}
                }
            }
            for (data, to) in answerer_outbox {
                assert_eq!(to, addr(40100));
                offerer
                    .handle(SessionInput::Packet(data.into(), addr(40101), now))
                    .unwrap();
            }

            if offerer_ready && answerer_ready {
                break;
            }

            if !progressed {
                now += Duration::from_millis(5);
                offerer.handle(SessionInput::Timeout(now)).unwrap();
                answerer.handle(SessionInput::Timeout(now)).unwrap();
            }
        }

        assert!(offerer_ready, "offerer never became ready");
        assert!(answerer_ready, "answerer never became ready");
        assert_eq!(offerer.remote_addr(), Some(addr(40101)));
        assert_eq!(answerer.remote_addr(), Some(addr(40100)));

        offerer
            .handle(SessionInput::Send(
                Channel::Reliable,
                Bytes::from_static(b"hello from offerer (reliable)"),
                now,
            ))
            .unwrap();
        offerer
            .handle(SessionInput::Send(
                Channel::Unreliable,
                Bytes::from_static(b"hello from offerer (unreliable)"),
                now,
            ))
            .unwrap();
        answerer
            .handle(SessionInput::Send(
                Channel::Reliable,
                Bytes::from_static(b"hello from answerer (reliable)"),
                now,
            ))
            .unwrap();
        answerer
            .handle(SessionInput::Send(
                Channel::Unreliable,
                Bytes::from_static(b"hello from answerer (unreliable)"),
                now,
            ))
            .unwrap();

        let mut offerer_received = Vec::new();
        let mut answerer_received = Vec::new();

        for _ in 0..200 {
            let mut progressed = false;

            let mut offerer_outbox = Vec::new();
            while let Some(output) = offerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => offerer_outbox.push((data, to)),
                    SessionOutput::Event(_) | SessionOutput::Wait(_) => {}
                    SessionOutput::Message(channel, data) => offerer_received.push((channel, data)),
                }
            }
            for (data, to) in offerer_outbox {
                answerer
                    .handle(SessionInput::Packet(data.into(), to, now))
                    .unwrap();
            }

            let mut answerer_outbox = Vec::new();
            while let Some(output) = answerer.poll() {
                progressed = true;
                match output {
                    SessionOutput::Send(data, to) => answerer_outbox.push((data, to)),
                    SessionOutput::Event(_) | SessionOutput::Wait(_) => {}
                    SessionOutput::Message(channel, data) => {
                        answerer_received.push((channel, data))
                    }
                }
            }
            for (data, to) in answerer_outbox {
                offerer
                    .handle(SessionInput::Packet(data.into(), to, now))
                    .unwrap();
            }

            if offerer_received.len() >= 2 && answerer_received.len() >= 2 {
                break;
            }

            if !progressed {
                now += Duration::from_millis(5);
                offerer.handle(SessionInput::Timeout(now)).unwrap();
                answerer.handle(SessionInput::Timeout(now)).unwrap();
            }
        }

        assert!(
            answerer_received
                .contains(&(Channel::Reliable, b"hello from offerer (reliable)".to_vec())),
            "answerer never received the reliable message: {answerer_received:?}"
        );
        assert!(
            answerer_received.contains(&(
                Channel::Unreliable,
                b"hello from offerer (unreliable)".to_vec()
            )),
            "answerer never received the unreliable message: {answerer_received:?}"
        );
        assert!(
            offerer_received.contains(&(
                Channel::Reliable,
                b"hello from answerer (reliable)".to_vec()
            )),
            "offerer never received the reliable message: {offerer_received:?}"
        );
        assert!(
            offerer_received.contains(&(
                Channel::Unreliable,
                b"hello from answerer (unreliable)".to_vec()
            )),
            "offerer never received the unreliable message: {offerer_received:?}"
        );
    }
}

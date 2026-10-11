//! A DTLS-secured SCTP session over ICE with the two NetherNet data channels.
mod dcep;
mod dtls;
mod ice;
mod sctp;

use crate::error::ProtocolError;
use crate::protocol::constants::{LOCAL_SCTP_MAX_MESSAGE_SIZE, SCTP_MAX_MESSAGE_SIZE};
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
const MAX_EARLY_PACKETS: usize = 8;
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
    ice: IceLayer,
    certificate: Option<rtc::dtls::crypto::Certificate>,

    pending_role_fingerprint: Option<(ResolvedRole, (String, String))>,
    remote_max_message_size: u32,
    early_packets: VecDeque<Vec<u8>>,

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
            sctp_max_message_size: LOCAL_SCTP_MAX_MESSAGE_SIZE,
            identity: None,
        };

        let session = Self {
            is_controlling,
            local_addr,
            ice,
            certificate: Some(certificate),
            pending_role_fingerprint: None,
            remote_max_message_size: SCTP_MAX_MESSAGE_SIZE,
            early_packets: VecDeque::new(),
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
        self.remote_max_message_size = match remote.sctp_max_message_size {
            0 => u32::MAX,
            size => size,
        };

        for candidate in candidates {
            self.ice.add_remote_candidate(candidate)?;
        }
        self.pending_role_fingerprint = Some((resolved_role, fingerprint));

        self.pump(now)
    }

    fn add_remote_candidate(
        &mut self,
        candidate: Candidate,
        now: Instant,
    ) -> Result<(), ProtocolError> {
        self.ice.add_remote_candidate(candidate)?;
        self.pump(now)
    }

    fn start_transports_on_selected_pair(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if self.dtls.is_some() {
            return Ok(());
        }
        let Some(remote_addr) = self.ice.selected_remote_addr() else {
            return Ok(());
        };
        let Some((resolved_role, fingerprint)) = self.pending_role_fingerprint.take() else {
            return Ok(());
        };
        self.start_transports(remote_addr, resolved_role, fingerprint, now)?;

        for packet in std::mem::take(&mut self.early_packets) {
            self.read_dtls(&packet, now)?;
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
            self.remote_max_message_size,
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

        if self.dtls.is_none() {
            if self.early_packets.len() < MAX_EARLY_PACKETS {
                self.early_packets.push_back(data.to_vec());
            }
            return Ok(());
        }

        self.read_dtls(data, now)?;
        self.pump(now)?;
        Ok(())
    }

    fn read_dtls(&mut self, data: &[u8], now: Instant) -> Result<(), ProtocolError> {
        if let Some(dtls) = &mut self.dtls {
            let events = dtls.handle_read(data, now)?;
            for event in events {
                self.handle_dtls_event(event, now);
            }
        }
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
        self.start_transports_on_selected_pair(now)?;

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
            SessionInput::Send(channel, data, now) => {
                self.send(channel, data, now)?;
                self.pump(now)
            }
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

    fn connected_pair() -> (Session, Session, Instant) {
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

        while offerer.poll().is_some() {}
        while answerer.poll().is_some() {}
        (offerer, answerer, now)
    }

    fn forward(
        from: &mut Session,
        to: &mut Session,
        (from_addr, to_addr): (SocketAddr, SocketAddr),
        ready: &mut bool,
        now: Instant,
    ) -> bool {
        let outputs: Vec<_> = std::iter::from_fn(|| from.poll()).collect();
        let progressed = !outputs.is_empty();
        for output in outputs {
            match output {
                SessionOutput::Send(data, dest) if dest == to_addr => to
                    .handle(SessionInput::Packet(data.into(), from_addr, now))
                    .unwrap(),
                SessionOutput::Event(SessionEvent::Ready) => *ready = true,
                _ => {}
            }
        }
        progressed
    }

    fn drive_until_ready(
        offerer: &mut Session,
        answerer: &mut Session,
        mut now: Instant,
    ) -> (bool, bool) {
        let (mut offerer_ready, mut answerer_ready) = (false, false);
        for _ in 0..5000 {
            let sent = (addr(40100), addr(40101));
            let answered = (addr(40101), addr(40100));
            let progressed = forward(offerer, answerer, sent, &mut offerer_ready, now)
                | forward(answerer, offerer, answered, &mut answerer_ready, now);
            if offerer_ready && answerer_ready {
                break;
            }
            if !progressed {
                now += Duration::from_millis(5);
                offerer.handle(SessionInput::Timeout(now)).unwrap();
                answerer.handle(SessionInput::Timeout(now)).unwrap();
            }
        }
        (offerer_ready, answerer_ready)
    }

    #[test]
    fn no_remote_address_is_reported_before_ice_selects_a_pair() {
        let now = Instant::now();
        let (mut offerer, _) = Session::new(addr(40100), true, now).unwrap();
        let (answerer, answer) = Session::new(addr(40101), false, now).unwrap();
        let answer_sdp = answer.encode_full(&[answerer.local_candidate().clone()]);
        let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();

        offerer
            .handle(SessionInput::RemoteDescription(
                parsed_answer,
                answer_candidates,
                now,
            ))
            .unwrap();

        assert_eq!(offerer.remote_addr(), None);
    }

    #[test]
    fn transports_follow_the_ice_selected_pair_past_a_dead_first_candidate() {
        let now = Instant::now();
        let (mut offerer, offer) = Session::new(addr(40100), true, now).unwrap();
        let (mut answerer, answer) = Session::new(addr(40101), false, now).unwrap();
        let (dead, _) = Session::new(addr(40199), false, now).unwrap();

        let offer_sdp = offer.encode_full(&[offerer.local_candidate().clone()]);
        let answer_sdp = answer.encode_full(&[
            dead.local_candidate().clone(),
            answerer.local_candidate().clone(),
        ]);
        let (parsed_offer, offer_candidates) = Description::parse(&offer_sdp).unwrap();
        let (parsed_answer, answer_candidates) = Description::parse(&answer_sdp).unwrap();
        assert_eq!(answer_candidates[0].addr(), addr(40199));

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

        let (offerer_ready, answerer_ready) = drive_until_ready(&mut offerer, &mut answerer, now);
        assert!(offerer_ready, "offerer never became ready");
        assert!(answerer_ready, "answerer never became ready");
        assert_eq!(offerer.remote_addr(), Some(addr(40101)));
    }

    #[test]
    fn a_send_is_written_without_waiting_for_a_timeout() {
        let (mut offerer, _answerer, now) = connected_pair();

        offerer
            .handle(SessionInput::Send(
                Channel::Reliable,
                Bytes::from_static(b"now"),
                now,
            ))
            .unwrap();

        let sent = std::iter::from_fn(|| offerer.poll())
            .any(|output| matches!(output, SessionOutput::Send(..)));
        assert!(sent, "the send stayed buffered until the next timeout");
    }

    fn reliable_messages_after_exchange(
        receiver: &mut Session,
        sender: &mut Session,
        mut now: Instant,
    ) -> Vec<Vec<u8>> {
        let mut received = Vec::new();
        for _ in 0..500 {
            let mut progressed = false;
            let outbox: Vec<_> = std::iter::from_fn(|| sender.poll()).collect();
            for output in outbox {
                if let SessionOutput::Send(data, to) = output {
                    progressed = true;
                    receiver
                        .handle(SessionInput::Packet(data.into(), to, now))
                        .unwrap();
                }
            }
            let outbox: Vec<_> = std::iter::from_fn(|| receiver.poll()).collect();
            for output in outbox {
                match output {
                    SessionOutput::Send(data, to) => {
                        progressed = true;
                        sender
                            .handle(SessionInput::Packet(data.into(), to, now))
                            .unwrap();
                    }
                    SessionOutput::Message(Channel::Reliable, data) => received.push(data),
                    _ => {}
                }
            }
            if !received.is_empty() {
                break;
            }
            if !progressed {
                now += Duration::from_millis(5);
                sender.handle(SessionInput::Timeout(now)).unwrap();
                receiver.handle(SessionInput::Timeout(now)).unwrap();
            }
        }
        received
    }

    #[test]
    fn we_advertise_the_vanilla_max_message_size() {
        let (_, offer) = Session::new(addr(40100), true, Instant::now()).unwrap();
        assert_eq!(offer.sctp_max_message_size, 262144);
    }

    #[test]
    fn a_peer_may_send_one_sctp_message_up_to_our_advertised_size() {
        let (mut offerer, mut answerer, now) = connected_pair();
        let payload = vec![7u8; 200_000];

        let stream_id = answerer.channels.stream_id(Channel::Reliable).unwrap();
        let mut stream = answerer
            .sctp
            .as_mut()
            .unwrap()
            .association_mut()
            .unwrap()
            .stream(stream_id)
            .unwrap();
        stream
            .write_with_ppi(
                now,
                &MessageSegment::new(0, Bytes::from(payload.clone())).encode(),
                PayloadProtocolIdentifier::Binary,
            )
            .expect("a 200 KB message fits the offerer's advertised max-message-size");
        answerer.pump(now).unwrap();

        let received = reliable_messages_after_exchange(&mut offerer, &mut answerer, now);
        assert_eq!(received, vec![payload]);
    }

    #[test]
    fn full_handshake_and_bidirectional_data_exchange() {
        let (mut offerer, mut answerer, mut now) = connected_pair();

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

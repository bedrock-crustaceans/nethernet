//! Signaling over the HTTP endpoint dedicated servers expose.
//!
//! A peer posts its offer to `/v1/join/{network id}` and the answer is the body of the
//! response, so a connection is negotiated in a single exchange and no candidate is ever
//! signaled on its own. The state machine below owns the routing, the limits and the
//! validation of the identity each offer carries, and leaves every socket operation, the
//! TLS and the HTTP framing itself to its caller.

pub mod config;
pub mod error;
pub mod input;
pub mod output;

use crate::identity::{PlayerInfo, validate_sdp};
use crate::protocol::packet::discovery::ServerData;
use crate::sans::Sans;
use crate::util::candidate;
use crate::util::endpoint;
use config::HttpSignalerConfig;
use error::HttpSignalerError;
use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use http::{Method, Request, Response, StatusCode, Version};
use input::{HttpSignalerInput, RejectReason};
use output::{HttpSignalerOutput, Offer};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// The header a reverse proxy names the originating client in.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// The path a peer posts its offer to.
const JOIN_PATH: &str = "/v1/join";

struct Connection {
    addr: SocketAddr,
    counted: bool,
}

struct Pending {
    connection: u64,
    keep_alive: bool,
    deadline: Instant,
}

/// The signaling of a single NetherNet network behind an HTTP endpoint.
pub struct HttpSignaler {
    config: HttpSignalerConfig,

    connections: HashMap<u64, Connection>,
    per_address: HashMap<IpAddr, usize>,
    pending: HashMap<u64, Pending>,
    server_data: Option<ServerData>,

    output: VecDeque<HttpSignalerOutput>,
}

impl Sans for HttpSignaler {
    type Input = HttpSignalerInput;
    type Output = HttpSignalerOutput;
    type Error = HttpSignalerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            HttpSignalerInput::Connected(connection, addr, _) => self.connected(connection, addr),
            HttpSignalerInput::Request {
                connection,
                request,
                proxied,
                now,
            } => self.handle_request(connection, &request, proxied, now)?,
            HttpSignalerInput::Answer { connection_id, sdp } => self.answer(connection_id, &sdp)?,
            HttpSignalerInput::Reject {
                connection_id,
                reason,
            } => self.reject(connection_id, reason)?,
            HttpSignalerInput::SetServerData(data) => self.server_data = Some(*data),
            HttpSignalerInput::Closed(connection) => self.closed(connection),
            HttpSignalerInput::Update(now) => self.handle_update(now)?,
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl HttpSignaler {
    pub fn new(config: HttpSignalerConfig) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            per_address: HashMap::new(),
            pending: HashMap::new(),
            server_data: None,
            output: VecDeque::new(),
        }
    }

    /// How many joins are waiting for an answer.
    pub fn pending_joins(&self) -> usize {
        self.pending.len()
    }

    /// How many connections are open, including the ones that have not asked for anything
    /// yet.
    pub fn connections(&self) -> usize {
        self.connections.len()
    }

    fn connected(&mut self, connection: u64, addr: SocketAddr) {
        let peer = endpoint::normalize(addr.ip());

        // Every client behind a trusted proxy shares its address, so they are not counted
        if self.config.trusted_proxies.contains(peer) {
            self.connections.insert(
                connection,
                Connection {
                    addr,
                    counted: false,
                },
            );
            return;
        }

        let held = self.per_address.entry(peer).or_insert(0);
        *held += 1;

        if *held > self.config.max_connections_per_address {
            *held -= 1;
            tracing::debug!(
                "refused a connection from {}, already holding {}",
                peer,
                self.config.max_connections_per_address
            );
            self.output.push_back(HttpSignalerOutput::Close(connection));
            return;
        }

        self.connections
            .insert(connection, Connection { addr, counted: true });
    }

    fn closed(&mut self, connection: u64) {
        let Some(entry) = self.connections.remove(&connection) else {
            return;
        };

        if entry.counted {
            let peer = endpoint::normalize(entry.addr.ip());
            if let Some(held) = self.per_address.get_mut(&peer) {
                *held = held.saturating_sub(1);
                if *held == 0 {
                    self.per_address.remove(&peer);
                }
            }
        }

        // A join whose connection is gone has nowhere to deliver its answer
        self.pending
            .retain(|_, pending| pending.connection != connection);
    }

    fn handle_request(
        &mut self,
        connection: u64,
        request: &Request<String>,
        proxied: Option<SocketAddr>,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        // A peer sends its status check and its join on one connection, so what it asked
        // for here decides whether the next request has anywhere to land
        let keep_alive = keep_alive(request);
        let path = request.uri().path().to_string();

        if path == JOIN_PATH {
            return self.status(connection, request, keep_alive);
        }

        let Some(network_id) = path
            .strip_prefix("/v1/join/")
            .filter(|id| !id.is_empty() && !id.contains('/'))
        else {
            return self.respond(connection, StatusCode::NOT_FOUND, keep_alive);
        };

        if request.method() != Method::POST {
            return self.respond(connection, StatusCode::METHOD_NOT_ALLOWED, keep_alive);
        }

        self.join(
            connection,
            network_id.to_string(),
            request,
            proxied,
            keep_alive,
            now,
        )
    }

    fn status(
        &mut self,
        connection: u64,
        request: &Request<String>,
        keep_alive: bool,
    ) -> Result<(), HttpSignalerError> {
        if request.method() != Method::GET {
            return self.respond(connection, StatusCode::METHOD_NOT_ALLOWED, keep_alive);
        }

        let Some(data) = self.server_data.as_ref().filter(|_| self.config.serve_motd) else {
            return self.respond(connection, StatusCode::SERVICE_UNAVAILABLE, keep_alive);
        };

        let body = data.to_json();
        self.respond_with(connection, body, "application/json", keep_alive)
    }

    fn join(
        &mut self,
        connection: u64,
        network_id: String,
        request: &Request<String>,
        proxied: Option<SocketAddr>,
        keep_alive: bool,
        now: Instant,
    ) -> Result<(), HttpSignalerError> {
        // Ahead of the signature check, so a flood cannot make us verify its way to the limit
        if self.pending.len() >= self.config.max_pending_joins {
            tracing::warn!(
                "refusing joins, {} are already waiting for an answer",
                self.pending.len()
            );
            return self.respond(connection, StatusCode::SERVICE_UNAVAILABLE, keep_alive);
        }

        let client_address = self.client_address(connection, request, proxied);
        let sdp = request.body();

        let player = match &self.config.token_trust {
            Some(trust) => match validate_sdp(sdp, trust, systemtime(now)) {
                Ok(claims) => Some(Box::new(PlayerInfo::new(
                    claims,
                    network_id.clone(),
                    client_address,
                ))),
                Err(e) => {
                    tracing::debug!("refusing an offer with an invalid identity: {}", e);
                    return self.respond(connection, StatusCode::UNAUTHORIZED, keep_alive);
                }
            },
            None => None,
        };

        // The network ID cannot double as the connection ID, it can fall outside the range
        let connection_id = rand::random::<u64>();
        self.pending.insert(
            connection_id,
            Pending {
                connection,
                keep_alive,
                deadline: now + self.config.answer_timeout,
            },
        );

        self.output
            .push_back(HttpSignalerOutput::Offer(Box::new(Offer {
                connection_id,
                network_id,
                sdp: sdp.clone(),
                client_address,
                host: request
                    .headers()
                    .get(HOST)
                    .and_then(|host| host.to_str().ok())
                    .map(str::to_string),
                player,
            })));

        Ok(())
    }

    fn answer(&mut self, connection_id: u64, sdp: &str) -> Result<(), HttpSignalerError> {
        let pending = self
            .pending
            .remove(&connection_id)
            .ok_or(HttpSignalerError::UnknownConnection(connection_id))?;

        let sdp = candidate::with_advertised_candidates(sdp, &self.config.advertised_addresses);
        self.respond_with(
            pending.connection,
            sdp,
            "application/sdp",
            pending.keep_alive,
        )
    }

    fn reject(
        &mut self,
        connection_id: u64,
        reason: RejectReason,
    ) -> Result<(), HttpSignalerError> {
        let pending = self
            .pending
            .remove(&connection_id)
            .ok_or(HttpSignalerError::UnknownConnection(connection_id))?;

        self.respond(pending.connection, status(reason), pending.keep_alive)
    }

    fn handle_update(&mut self, now: Instant) -> Result<(), HttpSignalerError> {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(&connection_id, _)| connection_id)
            .collect();

        for connection_id in expired {
            tracing::debug!("no answer was produced for connection {}", connection_id);
            self.reject(connection_id, RejectReason::Timeout)?;
        }

        let wait = self
            .pending
            .values()
            .map(|pending| pending.deadline.saturating_duration_since(now))
            .min()
            .unwrap_or(self.config.answer_timeout);

        self.output.push_back(HttpSignalerOutput::Wait(wait));
        Ok(())
    }

    /// The address of the peer, or the one a trusted proxy forwarded on its behalf.
    fn client_address(
        &self,
        connection: u64,
        request: &Request<String>,
        proxied: Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let remote = self.connections.get(&connection).map(|entry| entry.addr)?;
        if !self
            .config
            .trusted_proxies
            .contains(endpoint::normalize(remote.ip()))
        {
            return Some(remote);
        }

        // A PROXY header is the more trustworthy of the two, so it wins
        if let Some(proxied) = proxied {
            return Some(proxied);
        }

        let forwarded = request
            .headers()
            .get(FORWARDED_FOR)
            .and_then(|value| value.to_str().ok())?;

        // The leftmost entry is the originating client, and only an address literal is
        // read: resolving a name here would block on DNS and let the header stand for
        // whatever the answer happened to be
        let first = forwarded.split(',').next()?.trim();
        let first = first.strip_prefix('[').unwrap_or(first);
        let first = first.strip_suffix(']').unwrap_or(first);

        Some(SocketAddr::new(endpoint::parse(first)?, remote.port()))
    }

    fn respond(
        &mut self,
        connection: u64,
        status: StatusCode,
        keep_alive: bool,
    ) -> Result<(), HttpSignalerError> {
        let response = Response::builder()
            .status(status)
            .header(CONTENT_LENGTH, 0)
            .body(String::new())?;

        self.push(connection, response, keep_alive);
        Ok(())
    }

    fn respond_with(
        &mut self,
        connection: u64,
        body: String,
        content_type: &str,
        keep_alive: bool,
    ) -> Result<(), HttpSignalerError> {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, body.len())
            .body(body)?;

        self.push(connection, response, keep_alive);
        Ok(())
    }

    fn push(&mut self, connection: u64, response: Response<String>, keep_alive: bool) {
        self.output.push_back(HttpSignalerOutput::Response {
            connection,
            response: Box::new(response),
            keep_alive,
        });
    }
}

fn status(reason: RejectReason) -> StatusCode {
    match reason {
        RejectReason::Rejected => StatusCode::FORBIDDEN,
        RejectReason::Timeout => StatusCode::GATEWAY_TIMEOUT,
        RejectReason::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn keep_alive(request: &Request<String>) -> bool {
    let connection = request
        .headers()
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    match request.version() {
        Version::HTTP_10 => connection.eq_ignore_ascii_case("keep-alive"),
        _ => !connection.eq_ignore_ascii_case("close"),
    }
}

/// The wall clock an [`Instant`] falls on, which is what a token expiry is compared to.
///
/// The two clocks are read at the same moment, so the difference between them is the time
/// spent in this call rather than anything a token would notice.
fn systemtime(now: Instant) -> std::time::SystemTime {
    let elapsed = Instant::now().saturating_duration_since(now);
    std::time::SystemTime::now() - elapsed
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ServerIdentity, TokenTrust};
    use crate::util::ip_range::IpRangeSet;
    use std::time::{Duration, UNIX_EPOCH};

    const OFFER: &str = "v=0\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host generation 0\r\n\
        a=fingerprint:sha-256 AB:CD\r\n";

    fn signaler(config: HttpSignalerConfig) -> HttpSignaler {
        let mut signaler = HttpSignaler::new(config);
        signaler
            .handle(HttpSignalerInput::SetServerData(Box::new(ServerData::new(
                "Server".to_string(),
                "World".to_string(),
            ))))
            .unwrap();
        signaler
    }

    fn connect(signaler: &mut HttpSignaler, connection: u64, addr: &str) {
        signaler
            .handle(HttpSignalerInput::Connected(
                connection,
                addr.parse().unwrap(),
                Instant::now(),
            ))
            .unwrap();
    }

    fn request(method: Method, path: &str, body: &str) -> Box<Request<String>> {
        Box::new(
            Request::builder()
                .method(method)
                .uri(path)
                .body(body.to_string())
                .unwrap(),
        )
    }

    fn send(signaler: &mut HttpSignaler, connection: u64, request: Box<Request<String>>) {
        signaler
            .handle(HttpSignalerInput::Request {
                connection,
                request,
                proxied: None,
                now: Instant::now(),
            })
            .unwrap();
    }

    fn signed_offer() -> String {
        let identity = ServerIdentity::generate("example.com", std::time::SystemTime::now())
            .unwrap();
        identity.augment(OFFER).unwrap()
    }

    fn next(signaler: &mut HttpSignaler) -> HttpSignalerOutput {
        signaler.poll().expect("an output")
    }

    #[test]
    fn an_unknown_path_is_not_found() {
        let mut signaler = signaler(HttpSignalerConfig::default());
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(&mut signaler, 1, request(Method::GET, "/", ""));

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_status_endpoint_answers_with_the_server_data() {
        let mut signaler = signaler(HttpSignalerConfig::default());
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(&mut signaler, 1, request(Method::GET, "/v1/join", ""));

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.body().contains("Server"));
    }

    #[test]
    fn a_join_has_to_be_posted() {
        let mut signaler = signaler(HttpSignalerConfig::default());
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(&mut signaler, 1, request(Method::GET, "/v1/join/1234", ""));

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn an_offer_without_an_identity_is_refused() {
        let mut signaler = signaler(HttpSignalerConfig::default());
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(&mut signaler, 1, request(Method::POST, "/v1/join/1234", OFFER));

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(signaler.pending_joins(), 0);
    }

    #[test]
    fn an_offer_is_answered_by_the_transport() {
        let mut signaler = signaler(HttpSignalerConfig::default());
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(
            &mut signaler,
            1,
            request(Method::POST, "/v1/join/1234", &signed_offer()),
        );

        let HttpSignalerOutput::Offer(offer) = next(&mut signaler) else {
            panic!("expected an offer");
        };
        assert_eq!(offer.network_id, "1234");
        assert_eq!(
            offer.client_address,
            Some("127.0.0.1:1000".parse().unwrap())
        );
        assert!(offer.player.is_some());
        assert_eq!(signaler.pending_joins(), 1);

        signaler
            .handle(HttpSignalerInput::Answer {
                connection_id: offer.connection_id,
                sdp: "answer".to_string(),
            })
            .unwrap();

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), "answer");
        assert_eq!(signaler.pending_joins(), 0);
    }

    #[test]
    fn an_offer_no_one_answers_times_out() {
        let now = Instant::now();
        let mut signaler = signaler(HttpSignalerConfig {
            answer_timeout: Duration::from_secs(5),
            ..Default::default()
        });
        connect(&mut signaler, 1, "127.0.0.1:1000");
        signaler
            .handle(HttpSignalerInput::Request {
                connection: 1,
                request: request(Method::POST, "/v1/join/1234", &signed_offer()),
                proxied: None,
                now,
            })
            .unwrap();
        let _ = next(&mut signaler);

        signaler
            .handle(HttpSignalerInput::Update(now + Duration::from_secs(6)))
            .unwrap();

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn joins_are_capped_before_any_signature_is_checked() {
        let mut signaler = signaler(HttpSignalerConfig {
            max_pending_joins: 1,
            ..Default::default()
        });
        connect(&mut signaler, 1, "127.0.0.1:1000");
        connect(&mut signaler, 2, "127.0.0.1:1001");

        send(
            &mut signaler,
            1,
            request(Method::POST, "/v1/join/1234", &signed_offer()),
        );
        let _ = next(&mut signaler);

        send(&mut signaler, 2, request(Method::POST, "/v1/join/1234", OFFER));
        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn an_address_over_the_limit_is_closed() {
        let mut signaler = signaler(HttpSignalerConfig {
            max_connections_per_address: 1,
            ..Default::default()
        });

        connect(&mut signaler, 1, "203.0.113.5:1000");
        assert!(signaler.poll().is_none());

        connect(&mut signaler, 2, "203.0.113.5:1001");
        assert!(matches!(next(&mut signaler), HttpSignalerOutput::Close(2)));

        signaler.handle(HttpSignalerInput::Closed(1)).unwrap();
        connect(&mut signaler, 3, "203.0.113.5:1002");
        assert!(signaler.poll().is_none());
    }

    #[test]
    fn a_trusted_proxy_is_not_counted_and_speaks_for_its_clients() {
        let mut signaler = signaler(HttpSignalerConfig {
            max_connections_per_address: 1,
            trusted_proxies: IpRangeSet::parse(["10.0.0.0/8"]),
            token_trust: None,
            ..Default::default()
        });

        connect(&mut signaler, 1, "10.0.0.2:1000");
        connect(&mut signaler, 2, "10.0.0.2:1001");
        assert!(signaler.poll().is_none());

        let mut request = request(Method::POST, "/v1/join/1234", OFFER);
        request
            .headers_mut()
            .insert(FORWARDED_FOR, "93.184.216.34, 10.0.0.2".parse().unwrap());
        send(&mut signaler, 1, request);

        let HttpSignalerOutput::Offer(offer) = next(&mut signaler) else {
            panic!("expected an offer");
        };
        assert_eq!(
            offer.client_address,
            Some("93.184.216.34:1000".parse().unwrap())
        );
    }

    #[test]
    fn a_forwarded_header_from_an_untrusted_peer_is_ignored() {
        let mut signaler = signaler(HttpSignalerConfig {
            token_trust: None,
            ..Default::default()
        });
        connect(&mut signaler, 1, "203.0.113.5:1000");

        let mut request = request(Method::POST, "/v1/join/1234", OFFER);
        request
            .headers_mut()
            .insert(FORWARDED_FOR, "93.184.216.34".parse().unwrap());
        send(&mut signaler, 1, request);

        let HttpSignalerOutput::Offer(offer) = next(&mut signaler) else {
            panic!("expected an offer");
        };
        assert_eq!(
            offer.client_address,
            Some("203.0.113.5:1000".parse().unwrap())
        );
    }

    #[test]
    fn only_advertised_candidates_are_answered_with() {
        let mut signaler = signaler(HttpSignalerConfig {
            token_trust: None,
            advertised_addresses: vec!["192.168.1.10".to_string()],
            ..Default::default()
        });
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(&mut signaler, 1, request(Method::POST, "/v1/join/1234", OFFER));

        let HttpSignalerOutput::Offer(offer) = next(&mut signaler) else {
            panic!("expected an offer");
        };

        let answer = format!(
            "{}a=candidate:2 1 udp 2130706431 172.17.0.1 54322 typ host\r\n",
            OFFER
        );
        signaler
            .handle(HttpSignalerInput::Answer {
                connection_id: offer.connection_id,
                sdp: answer,
            })
            .unwrap();

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert!(response.body().contains("192.168.1.10"));
        assert!(!response.body().contains("172.17.0.1"));
    }

    #[test]
    fn a_closed_connection_takes_its_join_with_it() {
        let mut signaler = signaler(HttpSignalerConfig {
            token_trust: None,
            ..Default::default()
        });
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(&mut signaler, 1, request(Method::POST, "/v1/join/1234", OFFER));

        let HttpSignalerOutput::Offer(offer) = next(&mut signaler) else {
            panic!("expected an offer");
        };

        signaler.handle(HttpSignalerInput::Closed(1)).unwrap();
        assert_eq!(signaler.pending_joins(), 0);

        let error = signaler
            .handle(HttpSignalerInput::Answer {
                connection_id: offer.connection_id,
                sdp: "answer".to_string(),
            })
            .unwrap_err();
        assert!(matches!(error, HttpSignalerError::UnknownConnection(_)));
    }

    #[test]
    fn an_offer_signed_by_the_wrong_issuer_is_refused() {
        let keys = crate::identity::jwk::JwkSet::default();
        let mut signaler = signaler(HttpSignalerConfig {
            token_trust: Some(TokenTrust::Minecraft(keys)),
            ..Default::default()
        });
        connect(&mut signaler, 1, "127.0.0.1:1000");
        send(
            &mut signaler,
            1,
            request(Method::POST, "/v1/join/1234", &signed_offer()),
        );

        let HttpSignalerOutput::Response { response, .. } = next(&mut signaler) else {
            panic!("expected a response");
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn the_epoch_is_not_mistaken_for_now() {
        assert!(systemtime(Instant::now()) > UNIX_EPOCH);
    }
}

use crate::addr::Addr;
use crate::error::{NetherError, Result};
use crate::protocol::{Signal, SignalType};
use crate::transport::client::parse_error_code;
use futures::Stream;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use nethernet::prelude::{
    HttpSignaler, HttpSignalerConfig, HttpSignalerInput, HttpSignalerOutput, PlayerInfo,
    RejectReason, Sans, ServerData,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const MAX_BODY: u64 = 1 << 20;

const MAX_IDLE: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct HttpServerConfig {
    pub network_id: String,

    pub signaler: HttpSignalerConfig,

    pub tls: Option<Arc<rustls::ServerConfig>>,

    pub idle_timeout: Duration,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            network_id: String::new(),
            signaler: HttpSignalerConfig::default(),
            tls: None,
            idle_timeout: Duration::from_secs(30),
        }
    }
}

enum Command {
    Request {
        connection: u64,
        request: Box<http::Request<String>>,
        reply: oneshot::Sender<Response>,
    },
    Connected(u64, SocketAddr, oneshot::Sender<bool>),
    Closed(u64),
    Answer {
        connection_id: u64,
        sdp: String,
    },
    Reject {
        connection_id: u64,
        reason: RejectReason,
    },
    SetServerData(Box<ServerData>),
    Address(u64, oneshot::Sender<Option<SocketAddr>>),
    Player(u64, oneshot::Sender<Option<Arc<PlayerInfo>>>),
    Host(u64, oneshot::Sender<Option<String>>),
}

struct Response {
    response: http::Response<String>,
    keep_alive: bool,
}

pub struct HttpSignalingServer {
    network_id: String,
    local_addr: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
    signal_tx: broadcast::Sender<Signal>,
    cancel_token: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl HttpSignalingServer {
    pub async fn bind(addr: SocketAddr, config: HttpServerConfig) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;

        let (signal_tx, _) = broadcast::channel(64);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();

        let accept = Self::accept(
            listener,
            config.clone(),
            commands.clone(),
            cancel_token.clone(),
        );
        let task = Self::drive(
            HttpSignaler::new(config.signaler.clone()),
            command_rx,
            signal_tx.clone(),
            accept,
            cancel_token.clone(),
        );

        Ok(Self {
            network_id: config.network_id,
            local_addr,
            commands,
            signal_tx,
            cancel_token,
            task: Some(task),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    pub fn set_server_data(&self, server_data: ServerData) {
        let _ = self
            .commands
            .send(Command::SetServerData(Box::new(server_data)));
    }

    fn accept(
        listener: TcpListener,
        config: HttpServerConfig,
        commands: mpsc::UnboundedSender<Command>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let next_connection = AtomicU64::new(1);
            let acceptor = config.tls.clone().map(TlsAcceptor::from);

            loop {
                let (stream, peer) = tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            tracing::debug!("Failed to accept a connection: {}", e);
                            continue;
                        }
                    },
                };

                let connection = next_connection.fetch_add(1, Ordering::Relaxed);
                let (admitted_tx, admitted_rx) = oneshot::channel();
                if commands
                    .send(Command::Connected(connection, peer, admitted_tx))
                    .is_err()
                {
                    break;
                }

                if !admitted_rx.await.unwrap_or(false) {
                    continue;
                }

                let commands = commands.clone();
                let config = config.clone();
                let acceptor = acceptor.clone();
                let cancel_token = cancel_token.clone();

                tokio::spawn(async move {
                    let served = tokio::select! {
                        _ = cancel_token.cancelled() => Ok(()),
                        served = serve(stream, connection, config, acceptor, commands.clone()) => served,
                    };
                    if let Err(e) = served {
                        tracing::debug!("Connection from {} ended: {}", peer, e);
                    }
                    let _ = commands.send(Command::Closed(connection));
                });
            }
        })
    }

    fn drive(
        mut signaler: HttpSignaler,
        mut commands: mpsc::UnboundedReceiver<Command>,
        signal_tx: broadcast::Sender<Signal>,
        accept: JoinHandle<()>,
        cancel_token: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut waiting: HashMap<u64, oneshot::Sender<Response>> = HashMap::new();
            let mut addresses: HashMap<u64, SocketAddr> = HashMap::new();
            let mut players: HashMap<u64, Arc<PlayerInfo>> = HashMap::new();
            let mut hosts: HashMap<u64, String> = HashMap::new();
            let mut wake = Instant::now() + MAX_IDLE;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    command = commands.recv() => match command {
                        Some(Command::Connected(connection, addr, admitted)) => {
                            let _ = signaler.handle(HttpSignalerInput::Connected(
                                connection,
                                addr,
                                Instant::now(),
                            ));

                            let mut refused = false;
                            while let Some(output) = signaler.poll() {
                                if matches!(output, HttpSignalerOutput::Close(id) if id == connection) {
                                    refused = true;
                                }
                            }
                            let _ = admitted.send(!refused);
                        }
                        Some(Command::Request { connection, request, reply }) => {
                            waiting.insert(connection, reply);
                            if let Err(e) = signaler.handle(HttpSignalerInput::Request {
                                connection,
                                request,
                                now: Instant::now(),
                            }) {
                                tracing::debug!("Failed to handle a request: {}", e);
                            }
                        }
                        Some(Command::Closed(connection)) => {
                            waiting.remove(&connection);
                            let _ = signaler.handle(HttpSignalerInput::Closed(connection));
                        }
                        Some(Command::Answer { connection_id, sdp }) => {
                            if let Err(e) = signaler
                                .handle(HttpSignalerInput::Answer { connection_id, sdp })
                            {
                                tracing::debug!("Failed to deliver an answer: {}", e);
                            }
                            addresses.remove(&connection_id);
                            players.remove(&connection_id);
                            hosts.remove(&connection_id);
                        }
                        Some(Command::Reject { connection_id, reason }) => {
                            if let Err(e) = signaler
                                .handle(HttpSignalerInput::Reject { connection_id, reason })
                            {
                                tracing::debug!("Failed to reject a join: {}", e);
                            }
                            addresses.remove(&connection_id);
                            players.remove(&connection_id);
                            hosts.remove(&connection_id);
                        }
                        Some(Command::SetServerData(data)) => {
                            let _ = signaler.handle(HttpSignalerInput::SetServerData(data));
                        }
                        Some(Command::Address(connection_id, reply)) => {
                            let _ = reply.send(addresses.get(&connection_id).copied());
                        }
                        Some(Command::Host(connection_id, reply)) => {
                            let _ = reply.send(hosts.get(&connection_id).cloned());
                        }
                        Some(Command::Player(connection_id, reply)) => {
                            let _ = reply.send(players.get(&connection_id).cloned());
                        }
                        None => break,
                    },
                    _ = tokio::time::sleep_until(wake.into()) => {
                        let _ = signaler.handle(HttpSignalerInput::Update(Instant::now()));
                    }
                }

                while let Some(output) = signaler.poll() {
                    match output {
                        HttpSignalerOutput::Response {
                            connection,
                            response,
                            keep_alive,
                        } => {
                            if let Some(reply) = waiting.remove(&connection) {
                                let _ = reply.send(Response {
                                    response: *response,
                                    keep_alive,
                                });
                            }
                        }
                        HttpSignalerOutput::Close(connection) => {
                            waiting.remove(&connection);
                        }
                        HttpSignalerOutput::Offer(offer) => {
                            let offered = offer.signal();
                            if let Some(address) = offer.client_address {
                                addresses.insert(offer.connection_id, address);
                            }
                            if let Some(host) = offer.host {
                                hosts.insert(offer.connection_id, host);
                            }
                            if let Some(player) = offer.player {
                                players.insert(offer.connection_id, Arc::from(*player));
                            }

                            let _ = signal_tx.send(offered);
                        }
                        HttpSignalerOutput::Wait(wait) => {
                            wake = Instant::now() + wait.min(MAX_IDLE);
                        }
                    }
                }
            }

            accept.abort();
        })
    }
}

impl Drop for HttpSignalingServer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl HttpSignalingServer {
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        let command = match signal.signal_type {
            SignalType::Answer => Command::Answer {
                connection_id: signal.connection_id,
                sdp: signal.data,
            },
            SignalType::Error => Command::Reject {
                connection_id: signal.connection_id,
                reason: parse_error_code(&signal.data).into(),
            },
            signal_type => {
                return Err(NetherError::Other(format!(
                    "{} is not supported over HTTP signaling",
                    signal_type
                )));
            }
        };

        self.commands
            .send(command)
            .map_err(|_| NetherError::ConnectionClosed)
    }

    pub fn signals(&self) -> Pin<Box<dyn Stream<Item = Signal> + Send>> {
        let rx = self.signal_tx.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(signal) => return Some((signal, rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Signal receiver lagged, missed {} signals", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }

    pub fn network_id(&self) -> String {
        self.network_id.clone()
    }

    pub fn disable_trickle_ice(&self) -> bool {
        true
    }

    pub async fn remote_address(&self, addr: &Addr) -> Option<SocketAddr> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Address(addr.connection_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    pub async fn player(&self, addr: &Addr) -> Option<Arc<PlayerInfo>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Player(addr.connection_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    pub async fn host(&self, addr: &Addr) -> Option<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Host(addr.connection_id, reply_tx))
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    pub fn set_pong_data(&self, data: &[u8]) {
        match ServerData::from_pong_data(data) {
            Ok(server_data) => self.set_server_data(server_data),
            Err(e) => tracing::error!("Failed to parse pong data: {}", e),
        }
    }
}

async fn serve(
    stream: TcpStream,
    connection: u64,
    config: HttpServerConfig,
    acceptor: Option<TlsAcceptor>,
    commands: mpsc::UnboundedSender<Command>,
) -> Result<()> {
    match acceptor {
        Some(acceptor) => {
            let stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| NetherError::Other(format!("TLS handshake: {}", e)))?;
            serve_http(stream, connection, config, commands).await
        }
        None => serve_http(stream, connection, config, commands).await,
    }
}

async fn serve_http<S>(
    stream: S,
    connection: u64,
    config: HttpServerConfig,
    commands: mpsc::UnboundedSender<Command>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let commands = commands.clone();
        async move {
            let (parts, body) = request.into_parts();

            let body = match body.collect().await {
                Ok(body) => body.to_bytes(),
                Err(e) => {
                    tracing::debug!("Failed to read a request body: {}", e);
                    Bytes::new()
                }
            };
            if body.len() as u64 > MAX_BODY {
                return Ok::<_, hyper::Error>(
                    hyper::Response::builder()
                        .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Full::new(Bytes::new()))
                        .expect("a status and an empty body are always a valid response"),
                );
            }

            let request = http::Request::from_parts(
                parts,
                String::from_utf8_lossy(body.as_ref()).into_owned(),
            );

            let (reply_tx, reply_rx) = oneshot::channel();
            let sent = commands.send(Command::Request {
                connection,
                request: Box::new(request),
                reply: reply_tx,
            });

            let response = match sent {
                Ok(()) => reply_rx.await.ok(),
                Err(_) => None,
            };

            Ok(match response {
                Some(Response {
                    response,
                    keep_alive,
                }) => {
                    let (mut parts, body) = response.into_parts();
                    if !keep_alive {
                        parts
                            .headers
                            .insert(http::header::CONNECTION, "close".parse().expect("a header"));
                    }
                    hyper::Response::from_parts(parts, Full::new(Bytes::from(body)))
                }
                None => hyper::Response::builder()
                    .status(http::StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(Bytes::new()))
                    .expect("a status and an empty body are always a valid response"),
            })
        }
    });

    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(config.idle_timeout)
        .serve_connection(TokioIo::new(stream), service);

    connection
        .await
        .map_err(|e| NetherError::Other(format!("HTTP connection: {}", e)))
}

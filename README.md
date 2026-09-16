# NetherNet

The WebRTC-based network protocol used in newer versions of Minecraft. It provides LAN discovery and secure peer-to-peer (P2P) connectivity.

The workspace holds two crates:

- `nethernet` is sans-IO. It owns the wire formats, the identity assertions, the signaling state machines, and the WebRTC session itself (ICE, DTLS, SCTP, data channels, driven directly rather than through a generic peer connection), and performs no IO of its own, so it can be driven by any runtime.
- `nethernet-tokio` drives those state machines on Tokio over real sockets and exposes `NethernetListener` and `NethernetStream`.

- **Features:**
  - Secure communication over WebRTC (DTLS/SCTP)
  - LAN server discovery, with retransmission of unanswered signals
  - Signaling over LAN discovery or over the HTTP endpoint of a dedicated server, as a client and as a server
  - Identity assertions: offers are validated against the fingerprints they carry, and answers are signed with the identity of the server
  - Candidate inference for peers that gathered nothing a host on another network can reach
  - Connection limits, trusted proxies and the PROXY protocol on the HTTP endpoint
  - Easy-to-use `NethernetListener` and `NethernetStream`

## Usage

To build the project:

```bash
cargo build --release
```

To run the examples:

```bash
# NetherNet server
cargo run --example server -p nethernet-tokio

# NetherNet client
cargo run --example client -p nethernet-tokio

# List the servers advertising themselves on the local network
cargo run --example scanner -p nethernet-tokio
```

### Serving the HTTP endpoint

```rust,ignore
let signaling = HttpSignalingServer::bind(
    "0.0.0.0:19132".parse()?,
    HttpServerConfig {
        network_id: "1234".to_string(),
        tls: Some(nethernet_tokio::util::tls::from_pem("fullchain.pem", "key.pem").await?),
        ..Default::default()
    },
)
.await?;

// Required: a real client refuses any answer that carries no a=identity assertion.
let identity = nethernet_tokio::util::identity::from_pem_or_create("identity.pem", "example.com").await?;
let config = ConnectionConfig {
    identity: Some(Arc::new(identity)),
    ..Default::default()
};

let mut listener = NethernetListener::bind_with(signaling, config).await?;
let session = listener.accept().await?;
```

Answers are signed with the identity in `ConnectionConfig::identity`, which
`nethernet_tokio::util::identity::from_pem_or_create` loads from a PEM and creates on first
use. Clients pin that key, so it should be kept between restarts, and **every answer must
carry one** - a client refuses the connection otherwise, whether signaling ran over HTTPS
or plaintext HTTP. Offers are validated against `HttpSignalerConfig::token_trust`, which
defaults to accepting any self-signed token while still binding it to the certificate the
peer presents. `nethernet_tokio::util::jwks::Jwks::minecraft` fetches the keys needed to
require a token issued by the Minecraft authorization service instead.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

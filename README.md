# NetherNet

The WebRTC-based network protocol used in newer versions of Minecraft. It provides LAN discovery and secure peer-to-peer (P2P) connectivity.

- **Features:**
  - Secure communication over WebRTC (DTLS/SRTP)
  - LAN server discovery
  - Signaling management
  - Easy-to-use `NethernetListener` and `NethernetStream`

## Usage

To build the project:

```bash
cargo build --release
```

To run the examples:

```bash
# NetherNet Server
cargo run --example server -p nethernet

# NetherNet Client
cargo run --example client -p nethernet
```

## Requirements

- Rust 1.85 or higher

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

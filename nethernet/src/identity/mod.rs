//! Identity assertions carried in the SDP `a=identity` attribute (guide section 5).
pub mod envelope;
pub mod error;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod player;
pub mod server;
pub mod trust;

pub use envelope::{
    Assertion, Identity, Idp, canonical_fingerprint_json, fingerprint_payload, sdp_fingerprints,
};
pub use player::PlayerInfo;
pub use server::ServerIdentity;
pub use trust::{TokenTrust, validate_sdp};

/// Endpoint publishing the JWKS that signs Minecraft multiplayer tokens.
pub const MINECRAFT_KEYS_URL: &str =
    "https://authorization.franchise.minecraft-services.net/.well-known/keys";

/// Required `iss` of a token under `TokenTrust::Minecraft`.
pub const MINECRAFT_ISSUER: &str = "https://authorization.franchise.minecraft-services.net/";

/// Required `aud` entry of a token under `TokenTrust::Minecraft`.
pub const MINECRAFT_AUDIENCE: &str = "api://auth-minecraft-services/multiplayer";

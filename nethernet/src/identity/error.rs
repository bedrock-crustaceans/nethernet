use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("the description carries no identity")]
    Missing,

    #[error("malformed identity: {0}")]
    Malformed(String),

    #[error("untrusted token: {0}")]
    Untrusted(String),

    #[error("invalid client public key: {0}")]
    ClientPublicKey(String),

    #[error("fingerprint signature mismatch")]
    FingerprintMismatch,

    #[error("the description carries no fingerprints")]
    NoFingerprints,

    #[error("the login is signed with a key the transport was not opened with")]
    KeyMismatch,

    #[error("key error: {0}")]
    Key(String),

    #[error("signing failed: {0}")]
    Signing(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

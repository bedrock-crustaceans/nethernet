//! Errors raised while producing or validating an identity assertion.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    /// The description carries no `a=identity` attribute.
    #[error("the description carries no identity")]
    Missing,

    /// The identity, the token or the detached signature is malformed.
    #[error("malformed identity: {0}")]
    Malformed(String),

    /// The token is not signed by a trusted issuer, or its claims do not hold up.
    #[error("untrusted token: {0}")]
    Untrusted(String),

    /// The token carries no `cpk` claim, or it is not a key on P-384.
    #[error("invalid client public key: {0}")]
    ClientPublicKey(String),

    /// The detached signature does not cover the fingerprints of the description.
    #[error("fingerprint signature mismatch")]
    FingerprintMismatch,

    /// The description carries no DTLS fingerprint to bind the identity to.
    #[error("the description carries no fingerprints")]
    NoFingerprints,

    /// The identity that opened the transport does not hold the key the login is signed with.
    #[error("the login is signed with a key the transport was not opened with")]
    KeyMismatch,

    /// A key could not be generated, read or written.
    #[error("key error: {0}")]
    Key(String),

    /// An assertion could not be signed.
    #[error("signing failed: {0}")]
    Signing(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;

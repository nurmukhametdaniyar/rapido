use thiserror::Error;

/// Every failure mode in the workspace. Verification failures are distinct
/// variants so negative tests can assert *why* a check failed rather than just
/// that it did.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("point/scalar deserialization failed: {0}")]
    Deserialization(String),

    #[error("non-canonical encoding rejected: {0}")]
    NonCanonical(String),

    #[error("point is the identity element (context: {0})")]
    IdentityPoint(&'static str),

    #[error("point is not in the prime-order subgroup (context: {0})")]
    NotInSubgroup(&'static str),

    #[error("signature verification failed: {0}")]
    BadSignature(&'static str),

    #[error("credential epoch {got} is not the current epoch {want}")]
    EpochMismatch { got: u64, want: u64 },

    #[error("replayed presentation: nonce already seen")]
    Replay,

    #[error("credential has been revoked")]
    Revoked,

    #[error("proof of knowledge check failed: {0}")]
    BadProof(&'static str),

    #[error("escrow ciphertext is not well formed: {0}")]
    BadEscrow(&'static str),

    #[error("disclosed attribute set is invalid: {0}")]
    BadDisclosure(String),

    #[error("threshold: need {need} shares, got {got}")]
    NotEnoughShares { need: usize, got: usize },

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("audit log chain is broken at entry {0}")]
    BrokenChain(usize),

    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

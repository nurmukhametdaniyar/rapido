#![forbid(unsafe_code)]
//! `rapido-core` — shared types for the RAPIDO reference implementation.
//!
//! Contains: epoch arithmetic, domain-separation tags, canonical length-prefixed
//! encoding used for every signed/hashed message, the workspace error type, and
//! the environment-metadata header attached to every result file.

pub mod dst;
pub mod encoding;
pub mod epoch;
pub mod error;
pub mod meta;

pub use dst::Dst;
pub use encoding::Transcript;
pub use epoch::{Epoch, EpochClock};
pub use error::{Error, Result};
pub use meta::{EnvMeta, ResultFile};

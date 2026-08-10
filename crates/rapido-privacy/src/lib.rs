#![forbid(unsafe_code)]
//! `rapido-privacy` — Layer 2: differential privacy on response timing, plus
//! cover traffic.
//!
//! Three properties of this layer are easy to state wrongly, so they are made
//! explicit here and enforced by the code:
//!
//! 1. **Laplace noise on a delay is not implementable.** Laplace noise is
//!    negative half the time, and a delay cannot be negative. See
//!    [`mechanism`] for the shifted, truncated discrete mechanism used instead,
//!    and the `(ε, δ)` it actually provides.
//! 2. **Cover traffic increases bandwidth.** It buys unlinkability by sending
//!    packets that carry no work; the overhead is always an increase. See
//!    [`cover`].
//! 3. **A continuous-Laplace sampler on floats leaks the true value** through
//!    rounding, regardless of ε (Mironov, CCS 2012), so sampling here is exact
//!    discrete arithmetic — see [`discrete`].

pub mod accounting;
pub mod cover;
pub mod discrete;
pub mod mechanism;
pub mod sensitivity;

pub use accounting::Budget;
pub use cover::{CoverScheduler, CoverStats};
pub use mechanism::{
    AnyMechanism, EventKind, MBucket, MGeo, MPad, MechanismKind, NoMechanism, PrivacyParams,
    TimingMechanism,
};
pub use sensitivity::Sensitivity;

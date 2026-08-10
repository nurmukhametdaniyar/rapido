#![forbid(unsafe_code)]
//! `rapido-sim` — discrete-event simulation and adversary experiments.
//!
//! Every run is deterministic given a seed. Scenario results are produced from
//! at least ten independent seeds and reported as intervals rather than point
//! estimates.

pub mod attack;
pub mod des;
pub mod network;
pub mod scenario;
pub mod stats;
pub mod workload;

pub use network::NetworkModel;
pub use stats::{advantage_from_auc, auc, LatencyRecorder, LatencySummary};
pub use workload::{calibrate, CostProfile, SystemConfig};

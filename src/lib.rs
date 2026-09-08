//! HONEY-MIND / minotaur: low-interaction, bounded TCP deception sensor.
//!
//! The library exposes configuration validation, pre-bound listeners for
//! deterministic tests, structured session records, a supervised JSONL writer,
//! and a Prometheus text exporter. It never executes client commands.

#![forbid(unsafe_code)]

pub mod config;
pub mod logger;
pub mod metrics;
pub mod protocols;
pub mod ratelimit;
pub mod server;
pub mod session;

//! Low-interaction TCP honeypot with protocol emulation, JSONL logging, and
//! Prometheus metrics.
//!
//! See the binary entry point in `src/main.rs` and the README for usage.

pub mod config;
pub mod logger;
pub mod metrics;
pub mod protocols;
pub mod ratelimit;
pub mod server;
pub mod session;

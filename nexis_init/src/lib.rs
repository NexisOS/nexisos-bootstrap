//! # nexis-init
//!
//! PID 1 for NexisOS. Single-threaded `mio`/`epoll` event loop with
//! `pidfd`-based process supervision.
//!
//! ## Architecture
//!
//! All I/O is multiplexed through one `mio::Poll` instance:
//! - **pidfds** — one per supervised child, becomes readable on exit
//! - **signalfd** — SIGCHLD (zombie reaping), SIGTERM/SIGINT (shutdown)
//! - **notify socket** — sd_notify(3) protocol (READY=1, STATUS=, WATCHDOG=1)
//! - **control socket** — nexisctl commands (future)
//!
//! ## Design constraints
//!
//! - No async runtime (no tokio, no thread pool)
//! - No implicit allocations in the poll loop hot path
//! - Bounded memory footprint (~8 KB per supervised service)
//! - Must never panic — PID 1 cannot crash

pub mod cgroup;
pub mod config;
pub mod init;
pub mod manager;
pub mod notify;
pub mod pidfd;
pub mod service;
pub mod signal;

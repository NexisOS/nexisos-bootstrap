//! Signal handling via signal-hook-mio.
//!
//! Signals are blocked from normal delivery and delivered as readable
//! events on a mio-compatible fd. This eliminates signal handler
//! complexity — signals are just another event in the poll loop.
//!
//! Uses `signal-hook-mio` which handles sigprocmask and signalfd (on
//! Linux) internally. This replaces a manual nix/signalfd wrapper and
//! removes the `nix` crate from the dependency tree.

use std::io;

use mio::event::Source;
use mio::{Interest, Registry, Token};
use signal_hook::consts::signal::*;
use signal_hook_mio::v1_0::Signals;

/// Signals handled by PID 1.
const HANDLED: &[i32] = &[
    SIGCHLD, // Child process exited (backup for pidfd)
    SIGTERM, // Graceful shutdown request
    SIGINT,  // Ctrl-C (debug/console)
    SIGHUP,  // Configuration reload
];

/// Which signal was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSignal {
    /// A child process exited. Reap zombies not tracked by pidfd.
    ChildExited,
    /// Graceful shutdown requested (SIGTERM or SIGINT).
    Shutdown,
    /// Reload configuration (SIGHUP).
    Reload,
    /// Some other signal.
    Other(i32),
}

/// Wraps signal-hook-mio's `Signals` for use with mio.
pub struct SignalHandler {
    signals: Signals,
}

impl SignalHandler {
    /// Block handled signals and create a signal source for mio.
    ///
    /// Must be called before any threads are created (PID 1 is
    /// single-threaded, so this is always the case).
    pub fn new() -> io::Result<Self> {
        let signals = Signals::new(HANDLED)?;
        Ok(Self { signals })
    }

    /// Drain all pending signals, calling `f` for each one.
    pub fn drain<F>(&mut self, mut f: F)
    where
        F: FnMut(InitSignal),
    {
        for sig in self.signals.pending() {
            let init_sig = match sig {
                SIGCHLD => InitSignal::ChildExited,
                SIGTERM | SIGINT => InitSignal::Shutdown,
                SIGHUP => InitSignal::Reload,
                other => InitSignal::Other(other),
            };
            f(init_sig);
        }
    }
}

/// Delegate mio Source to the inner Signals fd.
impl Source for SignalHandler {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.signals.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.signals.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.signals.deregister(registry)
    }
}

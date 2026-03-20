//! Service state machine and runtime tracking.
//!
//! Each `ManagedService` holds configuration (from TOML) plus runtime state
//! (PID, pidfd, mio token, lifecycle state). The state machine matches the
//! lifecycle documented in the README:
//!
//! ```text
//! Inactive → Activating → Active → Deactivating → Inactive | Failed
//!                                                       ↓
//!                                                  Restarting → Activating
//! ```

use crate::config::ServiceConfig;
use crate::pidfd::PidFd;
use std::fmt;
use std::time::Instant;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Service lifecycle states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// Not running, not scheduled.
    Inactive,

    /// Dependencies resolved, ExecStartPre running or process spawned
    /// but readiness not yet confirmed (for Type=notify: waiting for READY=1).
    Activating,

    /// Process is running and confirmed ready.
    Active,

    /// ExecStop running, waiting for main process to exit.
    Deactivating,

    /// Process exited, waiting for `restart_sec` timer before restarting.
    Restarting,

    /// Exited with error and restart policy says stop.
    Failed { exit_code: i32 },
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inactive => write!(f, "inactive"),
            Self::Activating => write!(f, "activating"),
            Self::Active => write!(f, "active"),
            Self::Deactivating => write!(f, "deactivating"),
            Self::Restarting => write!(f, "restarting"),
            Self::Failed { exit_code } => write!(f, "failed (exit {})", exit_code),
        }
    }
}

// ---------------------------------------------------------------------------
// Managed service
// ---------------------------------------------------------------------------

/// A supervised service: configuration + runtime state.
pub struct ManagedService {
    /// Service name (key in services.toml).
    pub name: String,

    /// Parsed configuration.
    pub config: ServiceConfig,

    /// Current lifecycle state.
    pub state: ServiceState,

    /// PID of the main process (if running).
    pub pid: Option<i32>,

    /// pidfd registered with mio (if running).
    pub pidfd: Option<PidFd>,

    /// mio token assigned to this service's pidfd.
    pub token: Option<mio::Token>,

    /// When the service entered its current state.
    pub state_changed_at: Instant,

    /// Consecutive restart count since last manual start/stop.
    pub restart_count: u32,
}

impl ManagedService {
    pub fn new(name: String, config: ServiceConfig) -> Self {
        Self {
            name,
            config,
            state: ServiceState::Inactive,
            pid: None,
            pidfd: None,
            token: None,
            state_changed_at: Instant::now(),
            restart_count: 0,
        }
    }

    /// Transition to a new state, updating the timestamp and logging.
    pub fn set_state(&mut self, new_state: ServiceState) {
        log::info!("[{}] {} → {}", self.name, self.state, new_state);
        self.state = new_state;
        self.state_changed_at = Instant::now();
    }

    /// Should this service restart given how it exited?
    pub fn should_restart(&self, exit_code: i32) -> bool {
        match self.config.restart.as_str() {
            "always" => true,
            "on-failure" => exit_code != 0,
            "on-abnormal" => exit_code > 128, // killed by signal
            _ => false, // "no"
        }
    }

    /// True if this service uses the sd_notify readiness protocol.
    pub fn is_notify_type(&self) -> bool {
        self.config.service_type == "notify"
    }

    /// True if this service runs once and exits (no supervision).
    pub fn is_oneshot(&self) -> bool {
        self.config.service_type == "oneshot"
    }

    /// Seconds elapsed since entering the current state.
    pub fn state_age_secs(&self) -> u64 {
        self.state_changed_at.elapsed().as_secs()
    }

    /// Clear runtime state after process exits.
    pub fn clear_runtime(&mut self, poll: &mut mio::Poll) {
        if let Some(ref mut pidfd) = self.pidfd {
            let _ = poll.registry().deregister(pidfd);
        }
        self.pid = None;
        self.pidfd = None;
        self.token = None;
    }
}

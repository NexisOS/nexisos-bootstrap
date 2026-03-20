//! PID 1 entrypoint and main event loop.
//!
//! All I/O is multiplexed through a single `mio::Poll`:
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              mio::Poll (epoll)              │
//! │                                             │
//! │  Token 0: signalfd (SIGCHLD, SIGTERM, ...)  │
//! │  Token 1: sd_notify socket                  │
//! │  Token 2: control socket (nexisctl)         │
//! │  Token 1000+: pidfds (one per service)      │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! The loop is single-threaded with no async runtime. PID 1 must never
//! panic, so errors are logged and handled gracefully.

use std::io;
use std::time::Duration;

use mio::{Events, Interest, Poll, Token};

use crate::manager::ServiceManager;
use crate::notify::{self, NotifySocket};
use crate::pidfd;
use crate::signal::{InitSignal, SignalHandler};

// Reserved tokens for fixed fd sources.
const TOKEN_SIGNAL: Token = Token(0);
const TOKEN_NOTIFY: Token = Token(1);
// TOKEN(2) reserved for control socket (nexisctl — future)

/// Service config search paths.
const SERVICES_TOML: &str = "/etc/nexis/services.toml";

/// sd_notify socket path.
const NOTIFY_PATH: &str = "/run/nexis/notify";

/// Main entrypoint for nexis-init.
///
/// Call this from your binary crate's `main()`. This function never returns
/// under normal operation — PID 1 runs for the lifetime of the system.
pub fn run() -> io::Result<()> {
    log::info!("nexis-init starting");

    // ------------------------------------------------------------------
    // 1. Create the mio event loop
    // ------------------------------------------------------------------
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(256);

    // ------------------------------------------------------------------
    // 2. Set up signalfd (SIGCHLD, SIGTERM, SIGINT, SIGHUP)
    // ------------------------------------------------------------------
    let mut signal_handler = SignalHandler::new()?;
    poll.registry()
        .register(&mut signal_handler, TOKEN_SIGNAL, Interest::READABLE)?;
    log::info!("signalfd registered");

    // ------------------------------------------------------------------
    // 3. Set up sd_notify socket
    // ------------------------------------------------------------------
    let mut notify_socket = NotifySocket::bind(NOTIFY_PATH)?;
    poll.registry()
        .register(&mut notify_socket, TOKEN_NOTIFY, Interest::READABLE)?;
    log::info!("notify socket at {}", NOTIFY_PATH);

    // Create /run/systemd/notify → /run/nexis/notify for compat
    if let Err(e) = notify::create_compat_symlinks(notify_socket.path()) {
        log::warn!("systemd compat symlinks: {}", e);
    }

    // ------------------------------------------------------------------
    // 4. Initialize service manager and load config
    // ------------------------------------------------------------------
    let mut manager = ServiceManager::new();

    match manager.load_config(SERVICES_TOML) {
        Ok(count) => log::info!("loaded {} service definitions from {}", count, SERVICES_TOML),
        Err(e) => log::warn!("could not load {}: {}", SERVICES_TOML, e),
    }

    // ------------------------------------------------------------------
    // 5. Start all declared services
    // ------------------------------------------------------------------
    manager.start_all(&mut poll)?;

    // ------------------------------------------------------------------
    // 6. Main event loop
    // ------------------------------------------------------------------
    log::info!("entering event loop");

    loop {
        // Poll with 1s timeout to check restart timers
        if let Err(e) = poll.poll(&mut events, Some(Duration::from_secs(1))) {
            // EINTR is expected when signals arrive — just retry
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("poll error: {}", e);
            continue;
        }

        for event in events.iter() {
            match event.token() {
                TOKEN_SIGNAL => {
                    handle_signals(&mut signal_handler, &mut manager);
                }
                TOKEN_NOTIFY => {
                    handle_notify(&notify_socket, &mut manager)?;
                }
                token => {
                    // A pidfd became readable — a supervised process exited
                    match manager.handle_pidfd_event(token, &mut poll) {
                        Ok(Some((name, code))) => {
                            log::info!("[{}] exited (code {})", name, code);
                        }
                        Ok(None) => {
                            log::debug!("unknown token {:?}", token);
                        }
                        Err(e) => {
                            log::error!("pidfd event error: {}", e);
                        }
                    }
                }
            }
        }

        // Check for services whose restart timers have elapsed
        for name in manager.services_ready_to_restart() {
            log::info!("[{}] restart timer elapsed, restarting", name);
            if let Err(e) = manager.start_service(&name, &mut poll) {
                log::error!("[{}] restart failed: {}", name, e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

/// Drain all pending signals from the signalfd.
fn handle_signals(
    handler: &mut SignalHandler,
    manager: &mut ServiceManager,
) {
    handler.drain(|sig| match sig {
        InitSignal::ChildExited => {
            // Reap zombies from processes not tracked by pidfd
            // (e.g., grandchildren of forking daemons)
            pidfd::reap_zombies();
        }
        InitSignal::Shutdown => {
            log::info!("shutdown signal received — stopping all services");
            manager.stop_all();
            // PID 1 must not exit. In a real system, we would:
            // 1. Stop all services in reverse dependency order
            // 2. Unmount filesystems
            // 3. Call reboot(RB_POWER_OFF) or reboot(RB_AUTOBOOT)
            // For now, we just stop services and continue the loop.
        }
        InitSignal::Reload => {
            log::info!("reload signal received — reloading configuration");
            // TODO: re-read services.toml and diff against running state
            match manager.load_config(SERVICES_TOML) {
                Ok(count) => log::info!("reloaded {} services", count),
                Err(e) => log::error!("reload failed: {}", e),
            }
        }
        InitSignal::Other(n) => {
            log::debug!("unhandled signal {}", n);
        }
    });
}

/// Read all pending sd_notify messages.
fn handle_notify(
    socket: &NotifySocket,
    manager: &mut ServiceManager,
) -> io::Result<()> {
    while let Some(msg) = socket.recv()? {
        if msg.is_ready() {
            // For Type=notify services: transition Activating → Active
            if let Some(pid) = msg.main_pid() {
                manager.handle_notify_ready(pid);
            }
            // TODO: match by socket credentials (SCM_CREDENTIALS) instead
            // of relying on MAINPID field
        }

        if msg.is_watchdog() {
            if let Some(pid) = msg.main_pid() {
                manager.handle_watchdog_ping(pid);
            }
        }

        if let Some(status) = msg.status() {
            log::info!("service status: {}", status);
        }
    }
    Ok(())
}

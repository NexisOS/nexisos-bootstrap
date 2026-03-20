//! Service manager — orchestrates the lifecycle of all supervised services.
//!
//! Responsibilities:
//! - Load service configurations from TOML
//! - Spawn service processes with cgroup/namespace/seccomp/SELinux sandboxing
//! - Register pidfds with mio for exit notification
//! - Handle sd_notify readiness messages
//! - Manage restart timers and failure state
//! - Provide service status for nexisctl queries

use std::collections::HashMap;
use std::ffi::CString;
use std::io;

use crate::cgroup;
use crate::config::{self, ServiceConfig};
use crate::pidfd::{self, PidFd};
use crate::service::{ManagedService, ServiceState};

/// Pidfd tokens start here. 0–999 are reserved for signal, notify, control, etc.
const TOKEN_PIDFD_BASE: usize = 1000;

/// The service manager.
pub struct ServiceManager {
    /// All known services (by name).
    services: HashMap<String, ManagedService>,

    /// Maps mio token → service name for dispatching pidfd events.
    token_map: HashMap<mio::Token, String>,

    /// Next available mio token for pidfd registration.
    next_token: usize,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            token_map: HashMap::new(),
            next_token: TOKEN_PIDFD_BASE,
        }
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /// Load service definitions from a TOML config file.
    pub fn load_config(&mut self, path: &str) -> io::Result<usize> {
        let config = config::load_services(path)?;
        let count = config.services.len();
        for (name, svc_config) in config.services {
            log::info!("loaded service: {}", name);
            self.services
                .insert(name.clone(), ManagedService::new(name, svc_config));
        }
        Ok(count)
    }

    /// Register a service programmatically (for boot-critical services).
    pub fn register(&mut self, name: &str, config: ServiceConfig) {
        log::info!("registered service: {}", name);
        self.services
            .insert(name.to_string(), ManagedService::new(name.to_string(), config));
    }

    // -----------------------------------------------------------------------
    // Lifecycle — start
    // -----------------------------------------------------------------------

    /// Start a single service: spawn its process, create pidfd, register with mio.
    pub fn start_service(
        &mut self,
        name: &str,
        poll: &mut mio::Poll,
    ) -> io::Result<()> {
        let svc = self.services.get_mut(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown service: {}", name))
        })?;

        match svc.state {
            ServiceState::Active | ServiceState::Activating => {
                log::warn!("[{}] already running or starting", name);
                return Ok(());
            }
            _ => {}
        }

        svc.set_state(ServiceState::Activating);

        // --- Prepare exec args before fork (no allocations after fork) ---
        let exec_path = match CString::new(svc.config.exec.as_str()) {
            Ok(c) => c,
            Err(e) => {
                svc.set_state(ServiceState::Failed { exit_code: -1 });
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        };

        let mut c_args: Vec<CString> = vec![exec_path.clone()];
        for arg in &svc.config.args {
            match CString::new(arg.as_str()) {
                Ok(c) => c_args.push(c),
                Err(e) => {
                    svc.set_state(ServiceState::Failed { exit_code: -1 });
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }

        let env_pairs: Vec<(CString, CString)> = svc
            .config
            .env
            .iter()
            .filter_map(|(k, v)| {
                Some((CString::new(k.as_str()).ok()?, CString::new(v.as_str()).ok()?))
            })
            .collect();

        let workdir = svc.config.workdir.clone();
        let cgroup_config = svc.config.cgroup.clone();
        let service_name = name.to_string();

        // --- Create cgroup (best-effort, may fail in dev/container) ---
        let cgroup_path = cgroup::create_scope(&service_name, &cgroup_config)
            .map_err(|e| {
                log::warn!("[{}] cgroup setup: {}", service_name, e);
                e
            })
            .ok();

        // --- Fork child ---
        let (child_pid, mut child_pidfd) = pidfd::spawn_child(|| {
            // === Runs in child process after fork ===
            // Only async-signal-safe operations here.

            // Place into cgroup
            if let Some(ref cg) = cgroup_path {
                let _ = cgroup::place_pid(cg, unsafe { libc::getpid() });
            }

            // Set working directory
            if let Some(ref dir) = workdir {
                let _ = unsafe { libc::chdir(dir.as_ptr() as *const libc::c_char) };
            }

            // Set environment variables
            for (key, val) in &env_pairs {
                unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };
            }

            // TODO: enter namespaces (unshare)
            // TODO: load seccomp filter
            // TODO: SELinux setexeccon
            // TODO: drop capabilities

            // Build argv for execvp
            let argv: Vec<*const libc::c_char> = c_args
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            unsafe { libc::execvp(exec_path.as_ptr(), argv.as_ptr()) };

            // execvp only returns on error
            unsafe { libc::_exit(126) };
        })?;

        log::info!("[{}] spawned PID {}", name, child_pid);

        // --- Register pidfd with mio ---
        let token = mio::Token(self.next_token);
        self.next_token += 1;

        poll.registry().register(
            &mut child_pidfd,
            token,
            mio::Interest::READABLE,
        )?;

        // --- Update service state ---
        let svc = self.services.get_mut(name).unwrap();
        svc.pid = Some(child_pid);
        svc.pidfd = Some(child_pidfd);
        svc.token = Some(token);
        self.token_map.insert(token, name.to_string());

        // Type=simple: immediately active. Type=notify: stays Activating.
        if !svc.is_notify_type() {
            svc.set_state(ServiceState::Active);
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Lifecycle — stop
    // -----------------------------------------------------------------------

    /// Stop a service by sending SIGTERM to its main process.
    pub fn stop_service(&mut self, name: &str) -> io::Result<()> {
        let svc = self.services.get_mut(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown service: {}", name))
        })?;

        if let Some(pid) = svc.pid {
            svc.set_state(ServiceState::Deactivating);
            unsafe { libc::kill(pid, libc::SIGTERM) };
        } else {
            log::debug!("[{}] not running, nothing to stop", name);
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Event handling — pidfd
    // -----------------------------------------------------------------------

    /// Handle a pidfd becoming readable (child exited).
    /// Returns `(service_name, exit_code)` if a tracked service exited.
    pub fn handle_pidfd_event(
        &mut self,
        token: mio::Token,
        poll: &mut mio::Poll,
    ) -> io::Result<Option<(String, i32)>> {
        let name = match self.token_map.remove(&token) {
            Some(n) => n,
            None => return Ok(None),
        };

        let svc = match self.services.get_mut(&name) {
            Some(s) => s,
            None => return Ok(None),
        };

        let pid = svc.pid.unwrap_or(-1);
        let exit_code = pidfd::waitpid_nohang(pid)?.unwrap_or(-1);

        log::info!("[{}] PID {} exited with code {}", name, pid, exit_code);

        // Deregister pidfd from mio and clear runtime state
        svc.clear_runtime(poll);

        // Clean up cgroup scope (best-effort)
        let _ = cgroup::remove_scope(&name);

        // Decide next state
        if svc.should_restart(exit_code) {
            svc.restart_count += 1;
            svc.set_state(ServiceState::Restarting);
        } else if exit_code != 0 {
            svc.set_state(ServiceState::Failed { exit_code });
        } else {
            svc.restart_count = 0;
            svc.set_state(ServiceState::Inactive);
        }

        Ok(Some((name, exit_code)))
    }

    // -----------------------------------------------------------------------
    // Event handling — sd_notify
    // -----------------------------------------------------------------------

    /// A service sent READY=1 via sd_notify. Find it by PID and mark active.
    pub fn handle_notify_ready(&mut self, notify_pid: i32) {
        for svc in self.services.values_mut() {
            if svc.pid == Some(notify_pid) && svc.state == ServiceState::Activating {
                svc.set_state(ServiceState::Active);
                return;
            }
        }
        log::debug!("READY=1 from unknown PID {}", notify_pid);
    }

    /// A service sent a watchdog ping. Reset its watchdog timer.
    pub fn handle_watchdog_ping(&mut self, pid: i32) {
        for svc in self.services.values_mut() {
            if svc.pid == Some(pid) {
                // Reset the state timer (used for watchdog timeout detection)
                svc.state_changed_at = std::time::Instant::now();
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Restart scheduling
    // -----------------------------------------------------------------------

    /// Get services whose restart_sec timer has elapsed and are ready to restart.
    pub fn services_ready_to_restart(&self) -> Vec<String> {
        self.services
            .iter()
            .filter_map(|(name, svc)| {
                if svc.state == ServiceState::Restarting
                    && svc.state_age_secs() >= svc.config.restart_sec
                {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Bulk operations
    // -----------------------------------------------------------------------

    /// Start all registered services.
    ///
    /// TODO: Implement topological sort on the dependency graph
    /// (requires/after/before/wants) for correct parallel startup ordering.
    /// For now, starts in arbitrary order.
    pub fn start_all(&mut self, poll: &mut mio::Poll) -> io::Result<()> {
        let names: Vec<String> = self.services.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.start_service(&name, poll) {
                log::error!("[{}] failed to start: {}", name, e);
            }
        }
        Ok(())
    }

    /// Stop all services (for shutdown).
    pub fn stop_all(&mut self) {
        let names: Vec<String> = self.services.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.stop_service(&name) {
                log::error!("[{}] failed to stop: {}", name, e);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Status queries (for nexisctl)
    // -----------------------------------------------------------------------

    /// Snapshot of all services for status display.
    pub fn list_services(&self) -> Vec<ServiceStatus> {
        self.services
            .values()
            .map(|svc| ServiceStatus {
                name: svc.name.clone(),
                state: svc.state.to_string(),
                pid: svc.pid,
                restart_count: svc.restart_count,
                description: svc.config.description.clone(),
            })
            .collect()
    }

    /// Look up a single service.
    pub fn get_service(&self, name: &str) -> Option<&ManagedService> {
        self.services.get(name)
    }
}

/// Serializable status snapshot for nexisctl.
#[derive(Debug)]
pub struct ServiceStatus {
    pub name: String,
    pub state: String,
    pub pid: Option<i32>,
    pub restart_count: u32,
    pub description: Option<String>,
}

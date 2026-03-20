//! cgroups v2 service isolation.
//!
//! Each supervised service gets its own cgroup under the `nexis.slice`
//! hierarchy:
//!
//! ```text
//! /sys/fs/cgroup/
//!   nexis.slice/
//!     nginx.scope/          ← one scope per service
//!       cgroup.procs         (PIDs in this cgroup)
//!       memory.max           (from cgroup.memory_max)
//!       cpu.weight           (from cgroup.cpu_weight)
//!       pids.max             (from cgroup.pids_max or default 4096)
//! ```

use crate::config::CgroupConfig;
use std::io;
use std::path::{Path, PathBuf};

/// Base path for cgroup v2 unified hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Default PID limit per service.
const DEFAULT_PIDS_MAX: u64 = 4096;

/// Create a cgroup scope for a service and apply resource limits.
/// Returns the cgroup path for placing child processes.
pub fn create_scope(service_name: &str, config: &CgroupConfig) -> io::Result<PathBuf> {
    let scope = Path::new(CGROUP_ROOT)
        .join("nexis.slice")
        .join(format!("{}.scope", service_name));

    std::fs::create_dir_all(&scope)?;

    // Enable controllers in the parent slice if not already done
    let slice = Path::new(CGROUP_ROOT).join("nexis.slice");
    let _ = enable_controllers(&slice);

    // Memory limit
    if let Some(ref limit) = config.memory_max {
        let bytes = parse_size(limit)?;
        write_knob(&scope, "memory.max", &bytes.to_string())?;
    }

    // CPU weight (1–10000, default 100)
    if let Some(weight) = config.cpu_weight {
        write_knob(&scope, "cpu.weight", &weight.to_string())?;
    }

    // CPU quota (e.g. "50000 100000" = 50%)
    if let Some(ref quota) = config.cpu_quota {
        write_knob(&scope, "cpu.max", quota)?;
    }

    // IO weight
    if let Some(weight) = config.io_weight {
        write_knob(&scope, "io.weight", &weight.to_string())?;
    }

    // PID limit (default: 4096)
    let pids = config.pids_max.unwrap_or(DEFAULT_PIDS_MAX);
    write_knob(&scope, "pids.max", &pids.to_string())?;

    Ok(scope)
}

/// Move a process into a cgroup by writing its PID to `cgroup.procs`.
pub fn place_pid(cgroup_path: &Path, pid: i32) -> io::Result<()> {
    write_knob(cgroup_path, "cgroup.procs", &pid.to_string())
}

/// Remove a service's cgroup scope (after all processes have exited).
pub fn remove_scope(service_name: &str) -> io::Result<()> {
    let scope = Path::new(CGROUP_ROOT)
        .join("nexis.slice")
        .join(format!("{}.scope", service_name));
    if scope.exists() {
        std::fs::remove_dir(&scope)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Enable memory, cpu, io, pids controllers in a cgroup directory.
fn enable_controllers(path: &Path) -> io::Result<()> {
    let subtree = path.join("cgroup.subtree_control");
    if subtree.exists() {
        std::fs::write(&subtree, "+memory +cpu +io +pids")?;
    }
    Ok(())
}

/// Write a value to a cgroup knob file. Best-effort — logs and returns
/// errors but doesn't panic (cgroup knobs may not exist in all configs).
fn write_knob(cgroup: &Path, knob: &str, value: &str) -> io::Result<()> {
    let path = cgroup.join(knob);
    std::fs::write(&path, value).map_err(|e| {
        log::debug!("cgroup write {} = {:?}: {}", path.display(), value, e);
        e
    })
}

/// Parse human-readable sizes: "512M", "2G", "1024K", plain bytes.
fn parse_size(s: &str) -> io::Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('G') {
        (n, 1 << 30)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1 << 20)
    } else if let Some(n) = s.strip_suffix('K') {
        (n, 1 << 10)
    } else {
        (s, 1u64)
    };

    num.trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

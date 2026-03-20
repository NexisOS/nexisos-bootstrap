//! Service configuration parsing from TOML declarations.
//!
//! Reads `/etc/nexis/services.toml` and parses service definitions into
//! structured configs. Each service config compiles to the same internal
//! representation regardless of whether it came from TOML or a systemd
//! unit file (unit file parser is a future addition).
//!
//! # Example
//!
//! ```toml
//! [services.nginx]
//! exec = "/usr/sbin/nginx"
//! type = "notify"
//! restart = "on-failure"
//! restart_sec = 5
//! requires = ["network-online.target"]
//! after = ["network-online.target"]
//! cgroup.memory_max = "512M"
//! cgroup.cpu_weight = 100
//! seccomp = "default"
//! selinux.type = "httpd_t"
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::path::Path;

// ---------------------------------------------------------------------------
// Root config
// ---------------------------------------------------------------------------

/// Top-level structure of `services.toml`.
#[derive(Debug, Deserialize)]
pub struct ServicesConfig {
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
}

// ---------------------------------------------------------------------------
// Service config
// ---------------------------------------------------------------------------

/// Configuration for a single service.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Executable path (required).
    pub exec: String,

    /// Service type: "simple" | "forking" | "notify" | "oneshot"
    #[serde(rename = "type", default = "defaults::service_type")]
    pub service_type: String,

    /// Restart policy: "no" | "always" | "on-failure" | "on-abnormal"
    #[serde(default = "defaults::restart")]
    pub restart: String,

    /// Seconds to wait before restarting.
    #[serde(default = "defaults::restart_sec")]
    pub restart_sec: u64,

    /// Timeout for startup in seconds (0 = no timeout).
    #[serde(default = "defaults::timeout")]
    pub timeout_start_sec: u64,

    /// Timeout for shutdown in seconds.
    #[serde(default = "defaults::timeout")]
    pub timeout_stop_sec: u64,

    /// Watchdog interval in seconds (0 = disabled).
    #[serde(default)]
    pub watchdog_sec: u64,

    /// Hard dependencies — service fails if any of these aren't running.
    #[serde(default)]
    pub requires: Vec<String>,

    /// Soft dependencies — started if available, no failure propagation.
    #[serde(default)]
    pub wants: Vec<String>,

    /// Ordering — start this service after these.
    #[serde(default)]
    pub after: Vec<String>,

    /// Ordering — start this service before these.
    #[serde(default)]
    pub before: Vec<String>,

    /// Conflicting services — stop these when this starts.
    #[serde(default)]
    pub conflicts: Vec<String>,

    /// Command-line arguments appended to `exec`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables for the service process.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Working directory.
    pub workdir: Option<String>,

    /// Run as this user.
    pub user: Option<String>,

    /// Run as this group.
    pub group: Option<String>,

    /// Cgroup v2 resource limits.
    #[serde(default)]
    pub cgroup: CgroupConfig,

    /// SELinux domain transition settings.
    #[serde(default)]
    pub selinux: SelinuxConfig,

    /// Namespace isolation.
    #[serde(default)]
    pub namespaces: NamespaceConfig,

    /// Seccomp profile: "default", "strict", or a path to a custom profile.
    pub seccomp: Option<String>,

    /// Capabilities to retain.
    #[serde(default)]
    pub capabilities: CapabilityConfig,

    /// Description for status output and D-Bus.
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

/// cgroup v2 resource limits.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CgroupConfig {
    /// Memory limit, e.g. "512M", "2G"
    pub memory_max: Option<String>,
    /// CPU weight (1-10000, default 100)
    pub cpu_weight: Option<u32>,
    /// CPU quota, e.g. "50000 100000" (50% of one core)
    pub cpu_quota: Option<String>,
    /// IO weight (1-10000, default 100)
    pub io_weight: Option<u32>,
    /// Max number of PIDs
    pub pids_max: Option<u64>,
}

/// SELinux settings for a service.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SelinuxConfig {
    /// Domain type for transition at exec, e.g. "httpd_t"
    #[serde(rename = "type")]
    pub domain_type: Option<String>,
    /// File context rules
    #[serde(default)]
    pub file_contexts: Vec<FileContext>,
}

/// A single SELinux file context rule.
#[derive(Debug, Clone, Deserialize)]
pub struct FileContext {
    /// Path regex, e.g. "/var/www(/.*)?"
    pub path: String,
    /// SELinux context, e.g. "httpd_sys_content_t"
    pub context: String,
}

/// Linux namespace isolation options.
#[derive(Debug, Clone, Deserialize)]
pub struct NamespaceConfig {
    /// Mount namespace (default: true — isolate mounts)
    #[serde(rename = "mount", default = "defaults::yes")]
    pub mnt: bool,
    /// IPC namespace (default: true — isolate SysV IPC)
    #[serde(default = "defaults::yes")]
    pub ipc: bool,
    /// PID namespace (default: false)
    #[serde(default)]
    pub pid: bool,
    /// Network namespace (default: false — share host network)
    #[serde(default)]
    pub net: bool,
    /// UTS namespace (default: false)
    #[serde(default)]
    pub uts: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            mnt: true,
            ipc: true,
            pid: false,
            net: false,
            uts: false,
        }
    }
}

/// Capabilities to retain after exec.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CapabilityConfig {
    /// Ambient capabilities, e.g. ["NET_BIND_SERVICE"]
    #[serde(default)]
    pub ambient: Vec<String>,
    /// Bounding set (if empty, default restrictive set is used)
    #[serde(default)]
    pub bounding: Vec<String>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load and parse a services.toml file.
pub fn load_services<P: AsRef<Path>>(path: P) -> io::Result<ServicesConfig> {
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Load services from multiple config paths (base + profiles).
/// Later files override earlier ones for the same service name.
pub fn load_merged<P: AsRef<Path>>(paths: &[P]) -> io::Result<ServicesConfig> {
    let mut merged = HashMap::new();
    for path in paths {
        if path.as_ref().exists() {
            let config = load_services(path)?;
            merged.extend(config.services);
        }
    }
    Ok(ServicesConfig { services: merged })
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

mod defaults {
    pub fn service_type() -> String {
        "simple".into()
    }
    pub fn restart() -> String {
        "no".into()
    }
    pub fn restart_sec() -> u64 {
        5
    }
    pub fn timeout() -> u64 {
        30
    }
    pub fn yes() -> bool {
        true
    }
}

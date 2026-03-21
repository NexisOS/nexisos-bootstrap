use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Top-level guard.toml structure.
#[derive(Debug, Deserialize)]
pub struct GuardConfig {
    #[serde(default)]
    pub guard: GuardSection,
    #[serde(default)]
    pub antivirus: AntivirusSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub processes: ProcessesSection,
}

#[derive(Debug, Deserialize)]
pub struct GuardSection {
    /// "desktop", "server", or "router"
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Where to send alerts: "journal", "notify", "webhook"
    #[serde(default = "default_alert_targets")]
    pub alert: Vec<String>,
    /// Webhook URL if "webhook" is in alert targets
    pub webhook_url: Option<String>,
    /// Directory for generated backend configs
    #[serde(default = "default_run_dir")]
    pub run_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct AntivirusSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Real-time on-access scanning via clamonacc
    #[serde(default)]
    pub on_access: bool,
    /// Freshclam update interval (e.g. "6h", "12h")
    #[serde(default = "default_update_interval")]
    pub update_interval: String,
    /// Additional YARA rule directories
    #[serde(default)]
    pub extra_yara_rules: Option<PathBuf>,
    /// Paths to exclude from scanning
    #[serde(default)]
    pub exclude: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct NetworkSection {
    #[serde(default)]
    pub enabled: bool,
    /// "ids" (alert only) or "ips" (inline block)
    #[serde(default = "default_ids_mode")]
    pub mode: String,
    /// Network interfaces to monitor
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Rulesets: "emerging-threats", "abuse-ch", etc.
    #[serde(default = "default_rulesets")]
    pub rulesets: Vec<String>,
    /// Home network CIDR for Suricata HOME_NET
    #[serde(default = "default_home_net")]
    pub home_net: String,
}

#[derive(Debug, Deserialize)]
pub struct ProcessesSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Files to watch for unauthorized reads
    #[serde(default = "default_sensitive_files")]
    pub monitor_sensitive_files: Vec<PathBuf>,
    /// Alert when a service spawns an interactive shell
    #[serde(default = "default_true")]
    pub alert_on_shell_from_service: bool,
    /// Alert on setuid/setgid calls
    #[serde(default = "default_true")]
    pub alert_on_privilege_escalation: bool,
    /// Alert on kernel module loading
    #[serde(default = "default_true")]
    pub alert_on_kernel_module_load: bool,
    /// Binaries considered shells for detection
    #[serde(default = "default_shells")]
    pub shell_binaries: Vec<String>,
}

// ── Defaults ──

fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "desktop".into()
}

fn default_alert_targets() -> Vec<String> {
    vec!["journal".into()]
}

fn default_run_dir() -> PathBuf {
    PathBuf::from("/run/nexis-guard")
}

fn default_update_interval() -> String {
    "6h".into()
}

fn default_ids_mode() -> String {
    "ids".into()
}

fn default_rulesets() -> Vec<String> {
    vec!["emerging-threats".into()]
}

fn default_home_net() -> String {
    "192.168.0.0/16".into()
}

fn default_sensitive_files() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/shadow"),
        PathBuf::from("/etc/passwd"),
        PathBuf::from("/etc/sudoers"),
    ]
}

fn default_shells() -> Vec<String> {
    vec![
        "/bin/bash".into(),
        "/bin/sh".into(),
        "/bin/zsh".into(),
        "/bin/dash".into(),
    ]
}

impl Default for GuardSection {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            alert: default_alert_targets(),
            webhook_url: None,
            run_dir: default_run_dir(),
        }
    }
}

impl Default for AntivirusSection {
    fn default() -> Self {
        Self {
            enabled: true,
            on_access: false,
            update_interval: default_update_interval(),
            extra_yara_rules: None,
            exclude: Vec::new(),
        }
    }
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_ids_mode(),
            interfaces: Vec::new(),
            rulesets: default_rulesets(),
            home_net: default_home_net(),
        }
    }
}

impl Default for ProcessesSection {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_sensitive_files: default_sensitive_files(),
            alert_on_shell_from_service: true,
            alert_on_privilege_escalation: true,
            alert_on_kernel_module_load: true,
            shell_binaries: default_shells(),
        }
    }
}

/// Default config file location.
pub fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/nexis/guard.toml")
}

/// Load and parse the guard config from a TOML file.
pub fn load(path: &Path) -> Result<GuardConfig, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let config: GuardConfig = toml::from_str(&contents)?;
    Ok(config)
}

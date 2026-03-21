use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nexis-guard")]
#[command(about = "Unified security stack for NexisOS")]
#[command(version)]
pub struct Cli {
    /// Path to guard.toml config file
    #[arg(short, long, default_value = "/etc/nexis/guard.toml")]
    pub config: PathBuf,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start all enabled security services
    Start,

    /// Stop all running security services
    Stop,

    /// Show status of all backends
    Status,

    /// On-demand file or directory scan
    Scan {
        /// Path to scan
        path: PathBuf,
    },

    /// Generate backend configs from guard.toml without starting services
    Init,

    /// Stream unified alerts from all backends
    Logs {
        /// Only show alerts at or above this severity: info, warning, critical
        #[arg(short, long, default_value = "info")]
        severity: String,

        /// Follow (tail) the alert stream
        #[arg(short, long)]
        follow: bool,
    },

    /// Network IDS/IPS controls
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },

    /// Update signature databases (freshclam + suricata-update)
    Update,

    /// Show or validate the current configuration
    Config {
        /// Validate config without printing
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
pub enum NetworkAction {
    /// Show active network flows
    Flows,
    /// Manually block an IP or CIDR range
    Block {
        /// IP address or CIDR (e.g. 192.168.1.100 or 10.0.0.0/8)
        target: String,
    },
    /// Remove a manual block
    Unblock {
        /// IP address or CIDR to unblock
        target: String,
    },
    /// Show current block list
    Blocklist,
}

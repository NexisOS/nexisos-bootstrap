use crate::config::GuardConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tokio::process::{Child, Command};

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("failed to start {name}: {source}")]
    Start {
        name: String,
        source: std::io::Error,
    },
    #[error("failed to stop {name}: {source}")]
    Stop {
        name: String,
        source: std::io::Error,
    },
    #[error("{name} is not running")]
    NotRunning { name: String },
}

/// Tracks running backend processes.
pub struct ServiceManager {
    children: HashMap<String, Child>,
    run_dir: PathBuf,
}

impl ServiceManager {
    pub fn new(run_dir: PathBuf) -> Self {
        Self {
            children: HashMap::new(),
            run_dir,
        }
    }

    /// Start all enabled backends based on config.
    pub async fn start_all(&mut self, config: &GuardConfig) -> Result<(), ServiceError> {
        if config.antivirus.enabled {
            self.start_clamd(config).await?;
            if config.antivirus.on_access {
                self.start_clamonacc().await?;
            }
        }

        if config.network.enabled {
            self.start_suricata(config).await?;
        }

        if config.processes.enabled {
            self.start_tetragon().await?;
        }

        Ok(())
    }

    /// Stop all running backends.
    pub async fn stop_all(&mut self) -> Result<(), ServiceError> {
        let names: Vec<String> = self.children.keys().cloned().collect();
        for name in names {
            self.stop(&name).await?;
        }
        Ok(())
    }

    /// Check if a backend is running.
    pub fn is_running(&mut self, name: &str) -> bool {
        if let Some(child) = self.children.get_mut(name) {
            // try_wait returns Ok(Some(status)) if exited, Ok(None) if still running
            matches!(child.try_wait(), Ok(None))
        } else {
            false
        }
    }

    /// Get status of all known backends.
    pub fn status(&mut self) -> Vec<(String, bool)> {
        let names = ["clamd", "clamonacc", "suricata", "tetragon"];
        names
            .iter()
            .map(|n| (n.to_string(), self.is_running(n)))
            .collect()
    }

    async fn stop(&mut self, name: &str) -> Result<(), ServiceError> {
        if let Some(mut child) = self.children.remove(name) {
            child.kill().await.map_err(|e| ServiceError::Stop {
                name: name.to_string(),
                source: e,
            })?;
            tracing::info!("stopped {name}");
        }
        Ok(())
    }

    async fn start_clamd(&mut self, config: &GuardConfig) -> Result<(), ServiceError> {
        let conf_path = self.run_dir.join("clamav").join("clamd.conf");

        // Ensure log directory exists
        let log_dir = self.run_dir.join("clamav").join("log");
        std::fs::create_dir_all(&log_dir).ok();

        let child = Command::new("clamd")
            .arg("--config-file")
            .arg(&conf_path)
            .arg("--foreground")
            .spawn()
            .map_err(|e| ServiceError::Start {
                name: "clamd".into(),
                source: e,
            })?;

        tracing::info!("started clamd (pid {})", child.id().unwrap_or(0));
        self.children.insert("clamd".into(), child);
        Ok(())
    }

    async fn start_clamonacc(&mut self) -> Result<(), ServiceError> {
        let socket_path = self.run_dir.join("clamav").join("clamd.sock");

        let child = Command::new("clamonacc")
            .arg("--fdpass")
            .arg("--config-file")
            .arg(self.run_dir.join("clamav").join("clamd.conf"))
            .spawn()
            .map_err(|e| ServiceError::Start {
                name: "clamonacc".into(),
                source: e,
            })?;

        tracing::info!("started clamonacc (pid {})", child.id().unwrap_or(0));
        self.children.insert("clamonacc".into(), child);
        Ok(())
    }

    async fn start_suricata(&mut self, config: &GuardConfig) -> Result<(), ServiceError> {
        let conf_path = self.run_dir.join("suricata").join("suricata.yaml");
        let log_dir = self.run_dir.join("suricata").join("log");
        std::fs::create_dir_all(&log_dir).ok();

        let mut cmd = Command::new("suricata");
        cmd.arg("-c").arg(&conf_path);
        cmd.arg("-l").arg(&log_dir);

        // IPS mode uses --af-packet, IDS mode uses --af-packet too but without copy-mode
        cmd.arg("--af-packet");

        let child = cmd.spawn().map_err(|e| ServiceError::Start {
            name: "suricata".into(),
            source: e,
        })?;

        tracing::info!("started suricata (pid {})", child.id().unwrap_or(0));
        self.children.insert("suricata".into(), child);
        Ok(())
    }

    async fn start_tetragon(&mut self) -> Result<(), ServiceError> {
        let policy_dir = self.run_dir.join("tetragon");

        let child = Command::new("tetragon")
            .arg("--tracing-policy-dir")
            .arg(&policy_dir)
            .arg("--export-filename")
            .arg(self.run_dir.join("tetragon").join("events.json"))
            .spawn()
            .map_err(|e| ServiceError::Start {
                name: "tetragon".into(),
                source: e,
            })?;

        tracing::info!("started tetragon (pid {})", child.id().unwrap_or(0));
        self.children.insert("tetragon".into(), child);
        Ok(())
    }
}

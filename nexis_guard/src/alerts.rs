use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

/// Unified alert that all backends normalize into.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub source: AlertSource,
    pub summary: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSource {
    Tetragon,
    Suricata,
    Clamav,
}

/// Spawn background tasks that tail each backend's log file and send
/// normalized alerts into a single channel.
pub fn start_alert_stream(
    run_dir: PathBuf,
    enabled_backends: EnabledBackends,
) -> mpsc::Receiver<Alert> {
    let (tx, rx) = mpsc::channel(256);

    if enabled_backends.tetragon {
        let path = run_dir.join("tetragon").join("events.json");
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = tail_tetragon(path, tx).await {
                tracing::error!("tetragon alert stream error: {e}");
            }
        });
    }

    if enabled_backends.suricata {
        let path = run_dir.join("suricata").join("log").join("eve.json");
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = tail_suricata(path, tx).await {
                tracing::error!("suricata alert stream error: {e}");
            }
        });
    }

    if enabled_backends.clamav {
        let path = run_dir.join("clamav").join("log").join("clamd.log");
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = tail_clamav(path, tx).await {
                tracing::error!("clamav alert stream error: {e}");
            }
        });
    }

    rx
}

pub struct EnabledBackends {
    pub tetragon: bool,
    pub suricata: bool,
    pub clamav: bool,
}

// ── Backend-specific tailers ──

/// Wait for a file to appear, then open and tail it line by line.
async fn wait_and_open(path: PathBuf) -> Result<tokio::fs::File, std::io::Error> {
    loop {
        match tokio::fs::File::open(&path).await {
            Ok(f) => return Ok(f),
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

async fn tail_tetragon(path: PathBuf, tx: mpsc::Sender<Alert>) -> Result<(), Box<dyn std::error::Error + Send>> {
    let file = wait_and_open(path).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
            let process_name = event
                .pointer("/process/binary")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let policy_name = event
                .pointer("/policy_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let summary = format!("{policy_name}: {process_name}");

            let severity = match policy_name {
                name if name.contains("privilege") => Severity::Critical,
                name if name.contains("kernel-module") => Severity::Critical,
                name if name.contains("shell-from-service") => Severity::Critical,
                _ => Severity::Warning,
            };

            let alert = Alert {
                timestamp: Utc::now(),
                severity,
                source: AlertSource::Tetragon,
                summary,
                details: event,
            };

            if tx.send(alert).await.is_err() {
                break;
            }
        }
    }

    Ok(())
}

/// Suricata EVE JSON — we only care about event_type == "alert".
async fn tail_suricata(path: PathBuf, tx: mpsc::Sender<Alert>) -> Result<(), Box<dyn std::error::Error + Send>> {
    let file = wait_and_open(path).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
            let event_type = event
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if event_type != "alert" {
                continue;
            }

            let sig = event
                .pointer("/alert/signature")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown alert");

            let suricata_severity = event
                .pointer("/alert/severity")
                .and_then(|v| v.as_u64())
                .unwrap_or(3);

            let severity = match suricata_severity {
                1 => Severity::Critical,
                2 => Severity::Warning,
                _ => Severity::Info,
            };

            let src_ip = event.get("src_ip").and_then(|v| v.as_str()).unwrap_or("?");
            let dest_ip = event.get("dest_ip").and_then(|v| v.as_str()).unwrap_or("?");

            let alert = Alert {
                timestamp: Utc::now(),
                severity,
                source: AlertSource::Suricata,
                summary: format!("{sig} ({src_ip} -> {dest_ip})"),
                details: event,
            };

            if tx.send(alert).await.is_err() {
                break;
            }
        }
    }

    Ok(())
}

/// ClamAV clamd.log — look for "FOUND" lines.
async fn tail_clamav(path: PathBuf, tx: mpsc::Sender<Alert>) -> Result<(), Box<dyn std::error::Error + Send>> {
    let file = wait_and_open(path).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.contains("FOUND") {
            let alert = Alert {
                timestamp: Utc::now(),
                severity: Severity::Critical,
                source: AlertSource::Clamav,
                summary: line.clone(),
                details: serde_json::json!({ "raw": line }),
            };

            if tx.send(alert).await.is_err() {
                break;
            }
        }
    }

    Ok(())
}

impl Severity {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "warning" | "warn" => Self::Warning,
            _ => Self::Info,
        }
    }
}

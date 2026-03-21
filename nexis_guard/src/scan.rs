use std::path::Path;
use thiserror::Error;
use tokio::process::Command;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("clamdscan not found — is ClamAV installed?")]
    NotFound,
    #[error("scan failed: {0}")]
    Failed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result of an on-demand scan.
pub struct ScanResult {
    pub scanned: u32,
    pub infected: u32,
    pub findings: Vec<String>,
}

/// Run an on-demand scan on a file or directory using clamdscan.
/// Connects to the running clamd instance via its socket.
pub async fn scan_path(path: &Path, socket: &Path) -> Result<ScanResult, ScanError> {
    let output = Command::new("clamdscan")
        .arg("--fdpass")
        .arg("--stream")
        .arg(format!("--config-file=/dev/null"))
        .arg(format!("--socket={}", socket.display()))
        .arg("--infected")
        .arg("--no-summary")
        .arg(path)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ScanError::NotFound
            } else {
                ScanError::Io(e)
            }
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // clamdscan returns:
    //   0 = clean
    //   1 = infected found
    //   2 = error
    match output.status.code() {
        Some(2) => {
            return Err(ScanError::Failed(stderr.to_string()));
        }
        _ => {}
    }

    let findings: Vec<String> = stdout
        .lines()
        .filter(|line| line.contains("FOUND"))
        .map(|line| line.to_string())
        .collect();

    let infected = findings.len() as u32;

    // Count scanned files from a separate summary call
    let summary_output = Command::new("clamdscan")
        .arg("--fdpass")
        .arg(format!("--socket={}", socket.display()))
        .arg(path)
        .output()
        .await
        .ok();

    let scanned = summary_output
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout))
        .and_then(|out| {
            out.lines()
                .find(|l| l.starts_with("Scanned files:"))
                .and_then(|l| l.split_whitespace().last())
                .and_then(|n| n.parse::<u32>().ok())
        })
        .unwrap_or(0);

    Ok(ScanResult {
        scanned,
        infected,
        findings,
    })
}

/// Quick check: is the clamd socket reachable?
pub async fn is_clamd_available(socket: &Path) -> bool {
    Command::new("clamdscan")
        .arg("--ping")
        .arg(format!("--socket={}", socket.display()))
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

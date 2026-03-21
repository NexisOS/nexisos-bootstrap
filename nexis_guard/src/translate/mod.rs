pub mod clamav;
pub mod suricata;
pub mod tetragon;

use crate::config::GuardConfig;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranslateError {
    #[error("failed to write config: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Generate all backend config files into the run directory.
pub fn generate_all(config: &GuardConfig) -> Result<(), TranslateError> {
    let run_dir = &config.guard.run_dir;
    std::fs::create_dir_all(run_dir)?;

    if config.antivirus.enabled {
        clamav::generate(config, run_dir)?;
        tracing::info!("generated ClamAV config");
    }

    if config.network.enabled {
        suricata::generate(config, run_dir)?;
        tracing::info!("generated Suricata config");
    }

    if config.processes.enabled {
        tetragon::generate(config, run_dir)?;
        tracing::info!("generated Tetragon policies");
    }

    Ok(())
}

/// Helper to write a file, creating parent dirs as needed.
pub(crate) fn write_config(dir: &Path, filename: &str, contents: &str) -> Result<(), std::io::Error> {
    let path = dir.join(filename);
    std::fs::write(&path, contents)?;
    tracing::debug!("wrote {}", path.display());
    Ok(())
}

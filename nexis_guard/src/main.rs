use clap::Parser;
use nexis_guard::alerts::{self, EnabledBackends, Severity};
use nexis_guard::cli::{Cli, Command, NetworkAction};
use nexis_guard::config;
use nexis_guard::scan;
use nexis_guard::services::ServiceManager;
use nexis_guard::translate;
use owo_colors::OwoColorize;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Init tracing
    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    // Load config
    let cfg = config::load(&cli.config)?;

    match cli.command {
        Command::Init => {
            translate::generate_all(&cfg)?;
            println!("Generated backend configs in {}", cfg.guard.run_dir.display());
        }

        Command::Start => {
            translate::generate_all(&cfg)?;

            let mut mgr = ServiceManager::new(cfg.guard.run_dir.clone());
            mgr.start_all(&cfg).await?;

            println!("{} All enabled services started", "✓".green());

            // Block and stream alerts until interrupted
            let mut rx = alerts::start_alert_stream(
                cfg.guard.run_dir.clone(),
                EnabledBackends {
                    tetragon: cfg.processes.enabled,
                    suricata: cfg.network.enabled,
                    clamav: cfg.antivirus.enabled,
                },
            );

            // Handle shutdown gracefully
            let mut mgr_for_shutdown = mgr;
            tokio::select! {
                _ = async {
                    while let Some(alert) = rx.recv().await {
                        print_alert(&alert);
                    }
                } => {}
                _ = tokio::signal::ctrl_c() => {
                    println!("\nShutting down...");
                    mgr_for_shutdown.stop_all().await?;
                    println!("{} All services stopped", "✓".green());
                }
            }
        }

        Command::Stop => {
            let mut mgr = ServiceManager::new(cfg.guard.run_dir.clone());
            mgr.stop_all().await?;
            println!("{} All services stopped", "✓".green());
        }

        Command::Status => {
            let mut mgr = ServiceManager::new(cfg.guard.run_dir.clone());
            let statuses = mgr.status();

            println!("nexis-guard status\n");

            for (name, running) in &statuses {
                let indicator = if *running {
                    "●".green().to_string()
                } else {
                    "○".dimmed().to_string()
                };
                let state = if *running {
                    "running".green().to_string()
                } else {
                    "stopped".dimmed().to_string()
                };
                println!("  {indicator} {name:<12} {state}");
            }
        }

        Command::Scan { path } => {
            let socket = cfg.guard.run_dir.join("clamav").join("clamd.sock");

            if !scan::is_clamd_available(&socket).await {
                eprintln!("{} clamd is not running — start it with: nexis-guard start", "✗".red());
                std::process::exit(1);
            }

            println!("Scanning {}...", path.display());
            let result = scan::scan_path(&path, &socket).await?;

            if result.infected == 0 {
                println!("{} Clean — {} files scanned", "✓".green(), result.scanned);
            } else {
                println!(
                    "{} {} threat(s) found in {} files:\n",
                    "✗".red(),
                    result.infected,
                    result.scanned
                );
                for finding in &result.findings {
                    println!("  {finding}");
                }
                std::process::exit(1);
            }
        }

        Command::Logs { severity, follow } => {
            let min_severity = Severity::from_str_loose(&severity);

            if follow {
                let mut rx = alerts::start_alert_stream(
                    cfg.guard.run_dir.clone(),
                    EnabledBackends {
                        tetragon: cfg.processes.enabled,
                        suricata: cfg.network.enabled,
                        clamav: cfg.antivirus.enabled,
                    },
                );

                while let Some(alert) = rx.recv().await {
                    if alert.severity >= min_severity {
                        print_alert(&alert);
                    }
                }
            } else {
                println!("Use --follow to stream live alerts");
            }
        }

        Command::Network { action } => match action {
            NetworkAction::Block { target } => {
                println!("Blocking {target}...");
                let status = tokio::process::Command::new("nft")
                    .args(["add", "rule", "inet", "nexis-guard", "input",
                           "ip", "saddr", &target, "drop"])
                    .status()
                    .await?;

                if status.success() {
                    println!("{} Blocked {target}", "✓".green());
                } else {
                    eprintln!("{} Failed to block {target}", "✗".red());
                }
            }
            NetworkAction::Unblock { target } => {
                println!("Unblocking {target}...");
                // Listing and deleting specific nft rules requires handle lookup;
                // for now flush and re-apply is simplest
                println!("TODO: implement selective rule removal");
            }
            NetworkAction::Flows => {
                let output = tokio::process::Command::new("conntrack")
                    .args(["-L"])
                    .output()
                    .await;

                match output {
                    Ok(o) => print!("{}", String::from_utf8_lossy(&o.stdout)),
                    Err(_) => eprintln!("conntrack not available — install conntrack-tools"),
                }
            }
            NetworkAction::Blocklist => {
                let output = tokio::process::Command::new("nft")
                    .args(["list", "chain", "inet", "nexis-guard", "input"])
                    .output()
                    .await;

                match output {
                    Ok(o) => print!("{}", String::from_utf8_lossy(&o.stdout)),
                    Err(_) => eprintln!("nft not available"),
                }
            }
        },

        Command::Update => {
            println!("Updating ClamAV signatures...");
            let clam = tokio::process::Command::new("freshclam")
                .arg("--config-file")
                .arg(cfg.guard.run_dir.join("clamav").join("freshclam.conf"))
                .status()
                .await;

            match clam {
                Ok(s) if s.success() => println!("{} ClamAV signatures updated", "✓".green()),
                _ => eprintln!("{} freshclam failed", "✗".red()),
            }

            if cfg.network.enabled {
                println!("Updating Suricata rules...");
                let suri = tokio::process::Command::new("suricata-update")
                    .status()
                    .await;

                match suri {
                    Ok(s) if s.success() => println!("{} Suricata rules updated", "✓".green()),
                    _ => eprintln!("{} suricata-update failed", "✗".red()),
                }
            }
        }

        Command::Config { check } => {
            if check {
                // Config already parsed successfully above
                println!("{} Config is valid: {}", "✓".green(), cli.config.display());
            } else {
                let contents = std::fs::read_to_string(&cli.config)?;
                println!("{contents}");
            }
        }
    }

    Ok(())
}

fn print_alert(alert: &alerts::Alert) {
    let severity_str = match alert.severity {
        Severity::Info => "INFO".dimmed().to_string(),
        Severity::Warning => "WARN".yellow().to_string(),
        Severity::Critical => "CRIT".red().to_string(),
    };

    let source = format!("{:?}", alert.source).to_lowercase();
    let ts = alert.timestamp.format("%H:%M:%S");

    println!("{ts} [{severity_str}] [{source}] {}", alert.summary);
}

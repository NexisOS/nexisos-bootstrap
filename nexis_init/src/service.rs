use crate::pidfd::ChildProcess;
use std::path::PathBuf;
use std::process::Command;

/// Represents a system service
pub struct Service {
    pub name: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub child: Option<ChildProcess>,
}

impl Service {
    /// Create a new service
    pub fn new<S: Into<String>>(name: S, command: PathBuf, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            command,
            args,
            child: None,
        }
    }

    /// Start the service using pidfd
    pub fn start(&mut self) {
        if self.child.is_some() {
            println!("Service {} is already running", self.name);
            return;
        }

        let command = self.command.clone();
        let args = self.args.clone();

        let child_process = ChildProcess::spawn(move || {
            let err = Command::new(command)
                .args(args)
                .spawn()
                .expect("Failed to start service");
            // Child process should exit after executing command
            std::process::exit(err.id() as i32);
        });

        self.child = Some(child_process);
        println!("Service {} started", self.name);
    }

    /// Stop the service
    pub fn stop(&mut self) {
        if let Some(child) = &self.child {
            unsafe {
                libc::kill(child.pid.as_raw() as i32, libc::SIGTERM);
            }
            println!("Service {} stopped", self.name);
            self.child = None;
        } else {
            println!("Service {} is not running", self.name);
        }
    }

    /// Check if the service is running
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }
}

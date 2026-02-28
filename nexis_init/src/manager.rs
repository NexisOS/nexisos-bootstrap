use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::pidfd::ChildProcess;
use std::process::Command;

/// Represents a system service
#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub command: String,
    pub enabled: bool,
}

/// Global service registry
type ServiceRegistry = Arc<Mutex<HashMap<String, Service>>>;

/// Initialize the service manager (setup registry, etc.)
pub fn init() -> ServiceRegistry {
    let registry: ServiceRegistry = Arc::new(Mutex::new(HashMap::new()));
    println!("Service manager initialized");
    registry
}

/// Register a new service
pub fn register_service(
    registry: &ServiceRegistry,
    name: &str,
    command: &str,
    enabled: bool,
) {
    let service = Service {
        name: name.to_string(),
        command: command.to_string(),
        enabled,
    };
    registry.lock().unwrap().insert(name.to_string(), service);
    println!("Registered service: {}", name);
}

/// Start all enabled services and return their ChildProcess handles
pub fn start_services(registry: &ServiceRegistry) -> Vec<ChildProcess> {
    let services = registry.lock().unwrap();
    let mut children = Vec::new();

    for (name, service) in services.iter() {
        if service.enabled {
            println!("Starting service: {} ({})", name, service.command);

            // Spawn the service as a child process using pidfd
            let child = ChildProcess::spawn(|| {
                // Use exec to replace child process with the command
                let err = Command::new(&service.command)
                    .spawn()
                    .expect("Failed to spawn service")
                    .wait()
                    .expect("Service process failed");
                std::process::exit(err.code().unwrap_or(1));
            });

            children.push(child);
        }
    }

    children
}

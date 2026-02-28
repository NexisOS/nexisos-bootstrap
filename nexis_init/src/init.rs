pub mod manager;
pub mod service;
pub mod epoll;
pub mod pidfd;

/// Entrypoint for starting the init system
pub fn run_system_init() {
    println!("Starting Nexis Init System...");

    // Initialize the service manager
    let registry = manager::init();

    // Example: register some core services
    manager::register_service(&registry, "network", "/usr/bin/networkd", true);
    manager::register_service(&registry, "logger", "/usr/bin/loggerd", true);

    // Initialize the epoll manager
    let mut epoll_manager = epoll::EpollManager::new();

    // Start all enabled services and register them with epoll
    let children = manager::start_services(&registry);
    for child in children {
        epoll_manager.register_child(child);
    }

    // Start the epoll event loop (blocking)
    epoll_manager.run();
}

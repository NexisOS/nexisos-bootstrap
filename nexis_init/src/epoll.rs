use rustix::io::{epoll_create1, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollOp};
use rustix::io::close;
use std::collections::HashMap;

use crate::pidfd::ChildProcess;

/// Struct representing the epoll manager
pub struct EpollManager {
    epoll_fd: i32,
    children: HashMap<i32, ChildProcess>, // fd -> ChildProcess
}

impl EpollManager {
    /// Create a new epoll manager
    pub fn new() -> Self {
        let epoll_fd = epoll_create1(0).expect("Failed to create epoll instance");
        Self {
            epoll_fd,
            children: HashMap::new(),
        }
    }

    /// Register a child process with the epoll instance
    pub fn register_child(&mut self, child: ChildProcess) {
        let fd = child.as_fd();

        let mut event = EpollEvent::new(EpollFlags::IN | EpollFlags::HUP, fd as u64);
        epoll_ctl(self.epoll_fd, EpollOp::Add, fd, Some(&mut event))
            .expect("Failed to add child fd to epoll");

        self.children.insert(fd, child);
        println!("Registered child fd {} with epoll", fd);
    }

    /// Run the epoll event loop
    pub fn run(&mut self) {
        let mut events = [EpollEvent::empty(); 1024];

        loop {
            let n = epoll_wait(self.epoll_fd, &mut events, -1)
                .expect("Failed during epoll wait");

            for i in 0..n {
                let fd = events[i].data as i32;

                if let Some(child) = self.children.remove(&fd) {
                    // Wait for child exit
                    let exit_code = child.wait();
                    println!(
                        "Child process {} exited with code {}",
                        child.pid.as_raw(),
                        exit_code
                    );

                    // Cleanup epoll
                    epoll_ctl(self.epoll_fd, EpollOp::Del, fd, None)
                        .expect("Failed to remove fd from epoll");
                }
            }
        }
    }
}

impl Drop for EpollManager {
    fn drop(&mut self) {
        close(self.epoll_fd).expect("Failed to close epoll fd");
    }
}

use rustix::process::{fork, ForkResult, waitpid, Pid};
use rustix::fd::PidFd;
use rustix::process::PidFdFlags;
use rustix::io::close;
use std::os::unix::io::RawFd;

/// Represents a child process we want to monitor
pub struct ChildProcess {
    pub pid: Pid,
    pub pidfd: PidFd,
}

impl ChildProcess {
    /// Fork a new process and return a ChildProcess with pidfd
    pub fn spawn<F>(mut child_fn: F) -> Self
    where
        F: FnMut() -> !, // child function never returns
    {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                child_fn(); // execute child code
            }
            Ok(ForkResult::Parent { child }) => {
                // Create pidfd for the child
                let pidfd = PidFd::new(child, PidFdFlags::empty())
                    .expect("Failed to create pidfd");

                return Self {
                    pid: child,
                    pidfd,
                };
            }
            Err(e) => panic!("fork failed: {:?}", e),
        }
    }

    /// Wait for the child to exit (blocking)
    pub fn wait(&self) -> i32 {
        let status = waitpid(Some(self.pid)).expect("waitpid failed");
        status.raw() // return raw exit code
    }

    /// Get raw fd for epoll
    pub fn as_fd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // Closing pidfd
        let _ = close(self.pidfd.as_raw_fd());
    }
}

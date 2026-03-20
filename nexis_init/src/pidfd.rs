//! pidfd-based child process tracking.
//!
//! A pidfd is a file descriptor that refers to a specific process. When the
//! process exits, the fd becomes readable — this integrates directly into
//! mio's epoll loop without signal handlers or PID-reuse races.
//!
//! Current implementation: `fork()` + `pidfd_open(2)`.
//! Target implementation: `clone3(CLONE_PIDFD)` for atomic pidfd creation
//! (pending stable Rust wrappers for clone3).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};

// ---------------------------------------------------------------------------
// PidFd
// ---------------------------------------------------------------------------

/// File descriptor that tracks a specific child process.
/// Becomes readable when the process exits.
pub struct PidFd {
    fd: OwnedFd,
    pid: i32,
}

impl PidFd {
    /// Create a pidfd for an existing process via `pidfd_open(2)`.
    /// Requires Linux >= 5.3.
    pub fn open(pid: i32) -> io::Result<Self> {
        // pidfd_open(pid, flags) — flags=0 for default behavior
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0i32) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
        set_nonblocking(fd.as_raw_fd())?;
        set_cloexec(fd.as_raw_fd())?;
        Ok(Self { fd, pid })
    }

    /// The PID this fd tracks.
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Implement `mio::event::Source` so a PidFd can be registered with `mio::Poll`.
impl Source for PidFd {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).deregister(registry)
    }
}

// ---------------------------------------------------------------------------
// Child spawning
// ---------------------------------------------------------------------------

/// Spawn a child process and return `(child_pid, pidfd)`.
///
/// `pre_exec` runs in the child after fork, before exec. It should:
/// 1. Enter cgroup
/// 2. Set up namespaces
/// 3. Load seccomp filter
/// 4. Transition SELinux context
/// 5. Drop capabilities
/// 6. Call `exec_service()` or `libc::execvp()`
///
/// If `pre_exec` returns (exec failed), the child exits with code 126.
///
/// # Safety
///
/// After `fork()`, the child must only call async-signal-safe functions
/// until `exec`. This is safe for PID 1 because we are single-threaded.
pub fn spawn_child<F>(pre_exec: F) -> io::Result<(i32, PidFd)>
where
    F: FnOnce(),
{
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            // === Child process ===
            pre_exec();
            // If pre_exec returned, exec failed — exit immediately.
            // Use _exit (not exit) to avoid running parent's atexit handlers.
            unsafe { libc::_exit(126) };
        }
        child_pid => {
            // === Parent process ===
            // Immediately create a pidfd for the child.
            // Race window is negligible: only PID 1 is forking, and we
            // do this before returning to the event loop.
            let pidfd = PidFd::open(child_pid).map_err(|e| {
                // If pidfd_open fails, kill the orphan
                unsafe { libc::kill(child_pid, libc::SIGKILL) };
                e
            })?;
            Ok((child_pid, pidfd))
        }
    }
}

// ---------------------------------------------------------------------------
// waitpid helpers
// ---------------------------------------------------------------------------

/// Non-blocking reap of a child process. Returns `Some(exit_code)` if
/// the child has exited, `None` if still running.
pub fn waitpid_nohang(pid: i32) -> io::Result<Option<i32>> {
    let mut status: i32 = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else if ret == 0 {
        Ok(None)
    } else if libc::WIFEXITED(status) {
        Ok(Some(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        // Convention: 128 + signal_number
        Ok(Some(128 + libc::WTERMSIG(status)))
    } else {
        Ok(Some(-1))
    }
}

/// Reap all finished children (zombie cleanup).
/// Called on SIGCHLD for processes not tracked by pidfd.
pub fn reap_zombies() {
    loop {
        let ret = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if ret <= 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// fd helpers
// ---------------------------------------------------------------------------

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

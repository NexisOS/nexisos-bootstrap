//! sd_notify(3) protocol handler.
//!
//! Listens on a Unix datagram socket for KEY=VALUE messages from supervised
//! services. Supported fields:
//!
//! - `READY=1`      — service has finished starting
//! - `STATUS=...`   — human-readable status string
//! - `MAINPID=...`  — main PID of the service (for forking daemons)
//! - `WATCHDOG=1`   — watchdog keepalive ping
//! - `FDSTORE=1`    — file descriptor store request (future)
//!
//! The socket path is exported as `NOTIFY_SOCKET` so children inherit it.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};

// ---------------------------------------------------------------------------
// Parsed message
// ---------------------------------------------------------------------------

/// A parsed sd_notify message.
#[derive(Debug)]
pub struct NotifyMessage {
    /// KEY=VALUE fields from the message body.
    pub fields: HashMap<String, String>,
}

impl NotifyMessage {
    /// Service reports it has finished starting.
    pub fn is_ready(&self) -> bool {
        self.fields.get("READY").map_or(false, |v| v == "1")
    }

    /// Human-readable status line.
    pub fn status(&self) -> Option<&str> {
        self.fields.get("STATUS").map(|s| s.as_str())
    }

    /// Main PID override (for Type=forking services).
    pub fn main_pid(&self) -> Option<i32> {
        self.fields.get("MAINPID").and_then(|v| v.parse().ok())
    }

    /// Watchdog keepalive.
    pub fn is_watchdog(&self) -> bool {
        self.fields.get("WATCHDOG").map_or(false, |v| v == "1")
    }

    /// Service is stopping.
    pub fn is_stopping(&self) -> bool {
        self.fields.get("STOPPING").map_or(false, |v| v == "1")
    }

    /// Service is reloading configuration.
    pub fn is_reloading(&self) -> bool {
        self.fields.get("RELOADING").map_or(false, |v| v == "1")
    }
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

/// sd_notify socket listener.
///
/// Binds a Unix datagram socket and parses incoming sd_notify messages.
/// The socket fd is registered with mio for non-blocking reads.
pub struct NotifySocket {
    socket: UnixDatagram,
    path: PathBuf,
}

impl NotifySocket {
    /// Bind the notify socket at `path`.
    ///
    /// - Removes any stale socket file
    /// - Sets the socket to non-blocking mode
    /// - Exports `NOTIFY_SOCKET=<path>` for child processes
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Clean up stale socket from a previous boot
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let socket = UnixDatagram::bind(&path)?;
        socket.set_nonblocking(true)?;

        // Children read this env var to know where to send sd_notify messages
        std::env::set_var("NOTIFY_SOCKET", &path);

        Ok(Self { socket, path })
    }

    /// Read and parse a pending notify message.
    /// Returns `None` if no message is available (EWOULDBLOCK).
    pub fn recv(&self) -> io::Result<Option<NotifyMessage>> {
        let mut buf = [0u8; 4096];
        match self.socket.recv(&mut buf) {
            Ok(n) => {
                let text = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let fields = parse_fields(text);
                Ok(Some(NotifyMessage { fields }))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Socket path for symlink compatibility (/run/systemd/notify → here).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AsRawFd for NotifySocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl Source for NotifySocket {
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

impl Drop for NotifySocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse `KEY=VALUE\n` pairs from an sd_notify datagram.
fn parse_fields(text: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                fields.insert(key.to_string(), value.to_string());
            }
        }
    }
    fields
}

// ---------------------------------------------------------------------------
// Compatibility symlinks
// ---------------------------------------------------------------------------

/// Create /run/systemd/notify → /run/nexis/notify so applications that
/// hardcode the systemd notify path still work.
pub fn create_compat_symlinks(notify_path: &Path) -> io::Result<()> {
    let compat_dir = Path::new("/run/systemd");
    if !compat_dir.exists() {
        std::fs::create_dir_all(compat_dir)?;
    }

    let compat_path = compat_dir.join("notify");
    if compat_path.exists() {
        std::fs::remove_file(&compat_path)?;
    }

    std::os::unix::fs::symlink(notify_path, &compat_path)?;
    Ok(())
}

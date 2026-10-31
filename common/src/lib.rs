//! Shared wire protocol for the fleet agent and controller.
//!
//! The protocol is intentionally small and explicit. Every request carries an
//! authentication token and names one command from a fixed, auditable set.
//! There is deliberately **no** "run arbitrary command" verb: the agent only
//! exposes the administrative operations enumerated below.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bumped when the wire format changes in an incompatible way.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard cap on a single frame so a malformed or hostile peer cannot make the
/// other side allocate unbounded memory. 4 MiB is plenty for config/log tails.
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

/// A request from the controller to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub protocol: u32,
    /// Pre-shared token proving the caller is the owner's controller.
    pub token: String,
    pub command: Command,
}

impl Request {
    pub fn new(token: impl Into<String>, command: Command) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            token: token.into(),
            command,
        }
    }
}

/// The fixed set of administrative operations the agent will perform.
///
/// This is an allow-list by construction. To add a capability you edit this
/// enum and the matching handler — there is no generic shell escape hatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Command {
    /// Liveness/auth check.
    Ping,
    /// CPU, memory, disk, uptime, hostname, OS.
    SystemStatus,
    /// Enumerate installed Windows services and their state.
    ListServices,
    /// Query one service by name.
    ServiceStatus { name: String },
    /// Start/stop/restart a service. The service name MUST be present in the
    /// agent's configured `allowed_services` list, or the agent refuses.
    ServiceControl { name: String, action: ServiceAction },
    /// List the config keys the agent manages.
    ListConfig,
    /// Read one managed config value.
    GetConfig { key: String },
    /// Write one managed config value (persisted under the agent's config dir).
    PushConfig { key: String, value: String },
    /// Tail the last `lines` lines of a named, allow-listed log file.
    TailLog { name: String, lines: usize },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl std::fmt::Display for ServiceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceAction::Start => f.write_str("start"),
            ServiceAction::Stop => f.write_str("stop"),
            ServiceAction::Restart => f.write_str("restart"),
        }
    }
}

/// The agent's reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok { payload: Payload },
    /// A refusal or failure, with a human-readable reason. Never leaks secrets.
    Err { message: String },
}

impl Response {
    pub fn ok(payload: Payload) -> Self {
        Response::Ok { payload }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Response::Err {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    Pong {
        hostname: String,
        agent_version: String,
    },
    System(SystemStatus),
    Services {
        services: Vec<ServiceInfo>,
    },
    Service(ServiceInfo),
    ServiceControlResult {
        name: String,
        action: ServiceAction,
        detail: String,
    },
    ConfigKeys {
        keys: Vec<String>,
    },
    ConfigValue {
        key: String,
        value: Option<String>,
    },
    ConfigWritten {
        key: String,
    },
    LogLines {
        name: String,
        lines: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub hostname: String,
    pub os: String,
    pub kernel: Option<String>,
    pub uptime_secs: u64,
    pub cpu_usage_pct: f32,
    pub cpu_cores: usize,
    pub mem_total_bytes: u64,
    pub mem_used_bytes: u64,
    pub disks: Vec<DiskInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mount: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: String,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds limit of {max} bytes", max = MAX_FRAME_BYTES)]
    TooLarge(u32),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Write a length-prefixed JSON frame: `u32` big-endian length, then the bytes.
pub async fn write_frame<W, T>(w: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_FRAME_BYTES as u64 {
        return Err(FrameError::TooLarge(bytes.len() as u32));
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read a single length-prefixed JSON frame.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Constant-time comparison of two tokens, so a network attacker cannot learn
/// the token byte-by-byte from response timing.
pub fn tokens_match(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        // Still walk a fixed amount to avoid a trivial length oracle on the
        // common path; the length difference is already decisive, so just bail.
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

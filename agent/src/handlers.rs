//! Command handlers. Every handler is bounded: service control is restricted
//! to the configured allow-list, log tailing to named allow-listed files, and
//! config writes to a dedicated store directory. There is no arbitrary command
//! execution path.

use crate::config::AgentConfig;
use fleet_common::{
    Command, DiskInfo, Payload, Response, ServiceAction, ServiceInfo, SystemStatus,
};
use std::path::{Path, PathBuf};
use sysinfo::{Disks, System};

pub struct Context {
    pub config: AgentConfig,
    pub config_path: PathBuf,
    pub version: String,
}

impl Context {
    pub fn handle(&self, command: Command) -> Response {
        match command {
            Command::Ping => Response::ok(Payload::Pong {
                hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
                agent_version: self.version.clone(),
            }),
            Command::SystemStatus => Response::ok(Payload::System(system_status())),
            Command::ListServices => match list_services() {
                Ok(svcs) => Response::ok(Payload::Services { services: svcs }),
                Err(e) => Response::err(format!("listing services: {e}")),
            },
            Command::ServiceStatus { name } => match service_status(&name) {
                Ok(info) => Response::ok(Payload::Service(info)),
                Err(e) => Response::err(format!("service status for {name}: {e}")),
            },
            Command::ServiceControl { name, action } => self.service_control(&name, action),
            Command::ListConfig => self.list_config(),
            Command::GetConfig { key } => self.get_config(&key),
            Command::PushConfig { key, value } => self.push_config(&key, &value),
            Command::TailLog { name, lines } => self.tail_log(&name, lines),
        }
    }

    fn service_control(&self, name: &str, action: ServiceAction) -> Response {
        // Enforce the allow-list before touching anything.
        let allowed = self
            .config
            .allowed_services
            .iter()
            .any(|s| s.eq_ignore_ascii_case(name));
        if !allowed {
            tracing::warn!(service = name, %action, "refused: service not in allow-list");
            return Response::err(format!(
                "service '{name}' is not in allowed_services; refusing to {action}"
            ));
        }
        tracing::info!(service = name, %action, "service control requested");
        match control_service(name, action) {
            Ok(detail) => {
                tracing::info!(service = name, %action, "service control succeeded");
                Response::ok(Payload::ServiceControlResult {
                    name: name.to_string(),
                    action,
                    detail,
                })
            }
            Err(e) => {
                tracing::error!(service = name, %action, error = %e, "service control failed");
                Response::err(format!("{action} {name}: {e}"))
            }
        }
    }

    fn store_dir(&self) -> PathBuf {
        self.config.store_dir(&self.config_path)
    }

    fn list_config(&self) -> Response {
        let dir = self.store_dir();
        let mut keys = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(key) = name.strip_suffix(".val") {
                        keys.push(key.to_string());
                    }
                }
            }
        }
        keys.sort();
        Response::ok(Payload::ConfigKeys { keys })
    }

    fn get_config(&self, key: &str) -> Response {
        if let Err(e) = validate_key(key) {
            return Response::err(e);
        }
        let path = self.store_dir().join(format!("{key}.val"));
        match std::fs::read_to_string(&path) {
            Ok(v) => Response::ok(Payload::ConfigValue {
                key: key.to_string(),
                value: Some(v),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::ok(
                Payload::ConfigValue {
                    key: key.to_string(),
                    value: None,
                },
            ),
            Err(e) => Response::err(format!("reading config {key}: {e}")),
        }
    }

    fn push_config(&self, key: &str, value: &str) -> Response {
        if let Err(e) = validate_key(key) {
            return Response::err(e);
        }
        let dir = self.store_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return Response::err(format!("creating store dir: {e}"));
        }
        let path = dir.join(format!("{key}.val"));
        match std::fs::write(&path, value) {
            Ok(()) => {
                tracing::info!(key, bytes = value.len(), "config value written");
                Response::ok(Payload::ConfigWritten {
                    key: key.to_string(),
                })
            }
            Err(e) => Response::err(format!("writing config {key}: {e}")),
        }
    }

    fn tail_log(&self, name: &str, lines: usize) -> Response {
        let Some(path) = self.config.logs.get(name) else {
            return Response::err(format!("log '{name}' is not configured"));
        };
        let lines = lines.clamp(1, 5000);
        match tail_file(Path::new(path), lines) {
            Ok(out) => Response::ok(Payload::LogLines {
                name: name.to_string(),
                lines: out,
            }),
            Err(e) => Response::err(format!("tailing log {name}: {e}")),
        }
    }
}

/// Keys are restricted to a safe charset so a key can never escape the store
/// directory or collide with path separators.
fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 128 {
        return Err("config key must be 1..=128 characters".to_string());
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err("config key may only contain [A-Za-z0-9._-]".to_string());
    }
    Ok(())
}

fn system_status() -> SystemStatus {
    let mut sys = System::new();
    sys.refresh_memory();
    // CPU usage needs two samples spaced by a short interval.
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_usage();

    let disks = Disks::new_with_refreshed_list();
    let disk_info = disks
        .iter()
        .map(|d| DiskInfo {
            mount: d.mount_point().to_string_lossy().to_string(),
            total_bytes: d.total_space(),
            available_bytes: d.available_space(),
        })
        .collect();

    SystemStatus {
        hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
        os: System::long_os_version().unwrap_or_else(|| "unknown".into()),
        kernel: System::kernel_version(),
        uptime_secs: System::uptime(),
        cpu_usage_pct: sys.global_cpu_usage(),
        cpu_cores: sys.cpus().len(),
        mem_total_bytes: sys.total_memory(),
        mem_used_bytes: sys.used_memory(),
        disks: disk_info,
    }
}

// --- Service operations -----------------------------------------------------
//
// On Windows these shell out to PowerShell's service cmdlets, which return
// structured data and respect the Service Control Manager. On non-Windows
// builds (e.g. local development on Linux/macOS) they return a clear "not
// supported" result so the rest of the agent can still be exercised.

#[cfg(windows)]
fn list_services() -> anyhow::Result<Vec<ServiceInfo>> {
    let out = run_powershell(
        "Get-Service | Select-Object Name,DisplayName,@{N='Status';E={$_.Status.ToString()}} | ConvertTo-Json -Compress",
    )?;
    parse_services_json(&out)
}

#[cfg(windows)]
fn service_status(name: &str) -> anyhow::Result<ServiceInfo> {
    let script = format!(
        "Get-Service -Name {} | Select-Object Name,DisplayName,@{{N='Status';E={{$_.Status.ToString()}}}} | ConvertTo-Json -Compress",
        ps_quote(name)
    );
    let out = run_powershell(&script)?;
    let mut parsed = parse_services_json(&out)?;
    parsed
        .pop()
        .ok_or_else(|| anyhow::anyhow!("service '{name}' not found"))
}

#[cfg(windows)]
fn control_service(name: &str, action: ServiceAction) -> anyhow::Result<String> {
    let verb = match action {
        ServiceAction::Start => "Start-Service",
        ServiceAction::Stop => "Stop-Service",
        ServiceAction::Restart => "Restart-Service",
    };
    let script = format!("{verb} -Name {} -ErrorAction Stop", ps_quote(name));
    run_powershell(&script)?;
    Ok(format!("{action} issued for '{name}'"))
}

#[cfg(windows)]
fn run_powershell(script: &str) -> anyhow::Result<String> {
    use std::process::Command as PCommand;
    let output = PCommand::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("powershell failed: {}", stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Quote a value for safe interpolation into a single-quoted PowerShell string.
#[cfg(windows)]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(windows)]
fn parse_services_json(json: &str) -> anyhow::Result<Vec<ServiceInfo>> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // ConvertTo-Json emits a bare object for a single item, an array otherwise.
    let value: serde_json::Value = serde_json::from_str(trimmed)?;
    let items = match value {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };
    Ok(items
        .into_iter()
        .filter_map(|v| {
            Some(ServiceInfo {
                name: v.get("Name")?.as_str()?.to_string(),
                display_name: v
                    .get("DisplayName")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: v
                    .get("Status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
            })
        })
        .collect())
}

#[cfg(not(windows))]
fn list_services() -> anyhow::Result<Vec<ServiceInfo>> {
    anyhow::bail!("service enumeration is only supported on Windows")
}

#[cfg(not(windows))]
fn service_status(_name: &str) -> anyhow::Result<ServiceInfo> {
    anyhow::bail!("service status is only supported on Windows")
}

#[cfg(not(windows))]
fn control_service(_name: &str, _action: ServiceAction) -> anyhow::Result<String> {
    anyhow::bail!("service control is only supported on Windows")
}

/// Read the last `lines` lines of a file without loading the whole file when it
/// is large: read the tail in chunks from the end.
fn tail_file(path: &Path, lines: usize) -> anyhow::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut remaining = len;
    let mut buf: Vec<u8> = Vec::new();
    let mut newlines = 0usize;
    let chunk = 8192u64;

    while remaining > 0 && newlines <= lines {
        let read_size = chunk.min(remaining);
        remaining -= read_size;
        f.seek(SeekFrom::Start(remaining))?;
        let mut tmp = vec![0u8; read_size as usize];
        f.read_exact(&mut tmp)?;
        newlines += tmp.iter().filter(|&&b| b == b'\n').count();
        tmp.extend_from_slice(&buf);
        buf = tmp;
    }

    let text = String::from_utf8_lossy(&buf);
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    Ok(all[start..].iter().map(|s| s.to_string()).collect())
}

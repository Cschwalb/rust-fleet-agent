//! fleet-ctl — the controller CLI the owner runs to query and command a
//! fleet-agent on a machine they own.
//!
//! Connection parameters (agent address, token, pinned fingerprint) come from
//! flags, environment variables, or a small TOML profile file, in that order.

mod client;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use fleet_common::{Command as AgentCmd, Payload, Response, ServiceAction};

const TOKEN_ENV: &str = "FLEET_CTL_TOKEN";
const HOST_ENV: &str = "FLEET_CTL_HOST";
const FP_ENV: &str = "FLEET_CTL_FINGERPRINT";

#[derive(Parser)]
#[command(name = "fleet-ctl", version, about = "Controller for the fleet admin agent")]
struct Cli {
    /// Agent address as host:port (or set FLEET_CTL_HOST).
    #[arg(long, global = true)]
    host: Option<String>,
    /// Pinned certificate fingerprint (or set FLEET_CTL_FINGERPRINT).
    #[arg(long, global = true)]
    fingerprint: Option<String>,
    /// Auth token (prefer the FLEET_CTL_TOKEN env var over this flag).
    #[arg(long, global = true)]
    token: Option<String>,
    /// Emit raw JSON instead of a formatted table.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Liveness + auth check.
    Ping,
    /// CPU, memory, disk, uptime.
    Status,
    /// List all services.
    Services,
    /// Service subcommands.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Managed config subcommands.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Tail a named, allow-listed log file.
    Tail {
        name: String,
        #[arg(long, default_value_t = 100)]
        lines: usize,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Query one service.
    Status { name: String },
    /// Start a service (must be in the agent's allow-list).
    Start { name: String },
    /// Stop a service (must be in the agent's allow-list).
    Stop { name: String },
    /// Restart a service (must be in the agent's allow-list).
    Restart { name: String },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// List managed config keys.
    List,
    /// Read one config value.
    Get { key: String },
    /// Write one config value.
    Set { key: String, value: String },
}

struct Conn {
    host: String,
    port: u16,
    token: String,
    fingerprint: [u8; 32],
}

fn resolve_conn(cli: &Cli) -> Result<Conn> {
    let host_raw = cli
        .host
        .clone()
        .or_else(|| std::env::var(HOST_ENV).ok())
        .ok_or_else(|| anyhow!("no agent address; pass --host host:port or set {HOST_ENV}"))?;
    let (host, port) = split_host_port(&host_raw)?;

    let token = cli
        .token
        .clone()
        .or_else(|| std::env::var(TOKEN_ENV).ok())
        .ok_or_else(|| anyhow!("no token; set {TOKEN_ENV} (preferred) or pass --token"))?;

    let fp_raw = cli
        .fingerprint
        .clone()
        .or_else(|| std::env::var(FP_ENV).ok())
        .ok_or_else(|| {
            anyhow!("no pinned fingerprint; pass --fingerprint or set {FP_ENV}")
        })?;
    let fingerprint = client::parse_fingerprint(&fp_raw)?;

    Ok(Conn {
        host,
        port,
        token,
        fingerprint,
    })
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("address must be host:port, got '{s}'"))?;
    let port: u16 = p.parse().with_context(|| format!("bad port '{p}'"))?;
    Ok((h.to_string(), port))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conn = resolve_conn(&cli)?;

    let command = match &cli.command {
        Cmd::Ping => AgentCmd::Ping,
        Cmd::Status => AgentCmd::SystemStatus,
        Cmd::Services => AgentCmd::ListServices,
        Cmd::Service(sc) => match sc {
            ServiceCmd::Status { name } => AgentCmd::ServiceStatus { name: name.clone() },
            ServiceCmd::Start { name } => AgentCmd::ServiceControl {
                name: name.clone(),
                action: ServiceAction::Start,
            },
            ServiceCmd::Stop { name } => AgentCmd::ServiceControl {
                name: name.clone(),
                action: ServiceAction::Stop,
            },
            ServiceCmd::Restart { name } => AgentCmd::ServiceControl {
                name: name.clone(),
                action: ServiceAction::Restart,
            },
        },
        Cmd::Config(cc) => match cc {
            ConfigCmd::List => AgentCmd::ListConfig,
            ConfigCmd::Get { key } => AgentCmd::GetConfig { key: key.clone() },
            ConfigCmd::Set { key, value } => AgentCmd::PushConfig {
                key: key.clone(),
                value: value.clone(),
            },
        },
        Cmd::Tail { name, lines } => AgentCmd::TailLog {
            name: name.clone(),
            lines: *lines,
        },
    };

    let response = client::send(&conn.host, conn.port, conn.fingerprint, &conn.token, command)
        .await?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_human(&response);
    }

    // Non-zero exit on an agent-side error so scripts can detect failure.
    if matches!(response, Response::Err { .. }) {
        std::process::exit(1);
    }
    Ok(())
}

fn print_human(response: &Response) {
    match response {
        Response::Err { message } => eprintln!("error: {message}"),
        Response::Ok { payload } => match payload {
            Payload::Pong {
                hostname,
                agent_version,
            } => println!("pong from {hostname} (agent v{agent_version})"),
            Payload::System(s) => {
                println!("Host:    {}", s.hostname);
                println!("OS:      {}", s.os);
                if let Some(k) = &s.kernel {
                    println!("Kernel:  {k}");
                }
                println!("Uptime:  {}", fmt_duration(s.uptime_secs));
                println!("CPU:     {:.1}% over {} cores", s.cpu_usage_pct, s.cpu_cores);
                println!(
                    "Memory:  {} / {} ({:.0}%)",
                    fmt_bytes(s.mem_used_bytes),
                    fmt_bytes(s.mem_total_bytes),
                    pct(s.mem_used_bytes, s.mem_total_bytes)
                );
                for d in &s.disks {
                    let used = d.total_bytes.saturating_sub(d.available_bytes);
                    println!(
                        "Disk {:<8} {} / {} ({:.0}%)",
                        d.mount,
                        fmt_bytes(used),
                        fmt_bytes(d.total_bytes),
                        pct(used, d.total_bytes)
                    );
                }
            }
            Payload::Services { services } => {
                println!("{:<32} {:<10} {}", "NAME", "STATUS", "DISPLAY NAME");
                for s in services {
                    println!("{:<32} {:<10} {}", s.name, s.status, s.display_name);
                }
                println!("\n{} services", services.len());
            }
            Payload::Service(s) => {
                println!("{} [{}] — {}", s.name, s.status, s.display_name);
            }
            Payload::ServiceControlResult {
                name,
                action,
                detail,
            } => println!("{action} {name}: {detail}"),
            Payload::ConfigKeys { keys } => {
                if keys.is_empty() {
                    println!("(no config keys)");
                } else {
                    for k in keys {
                        println!("{k}");
                    }
                }
            }
            Payload::ConfigValue { key, value } => match value {
                Some(v) => println!("{key} = {v}"),
                None => println!("{key} is not set"),
            },
            Payload::ConfigWritten { key } => println!("wrote {key}"),
            Payload::LogLines { name, lines } => {
                println!("--- {name} ({} lines) ---", lines.len());
                for l in lines {
                    println!("{l}");
                }
            }
        },
    }
}

fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

fn fmt_duration(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    format!("{d}d {h}h {m}m")
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

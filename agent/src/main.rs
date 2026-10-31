//! fleet-agent — an overt, authenticated remote administration agent for
//! machines you own.
//!
//! Design principles:
//!  * Overt: installs as a normal, named Windows service; logs to a visible
//!    file; shows up in services.msc and Task Manager. No hiding, no
//!    persistence tricks, no anti-detection.
//!  * Authenticated + encrypted: every connection is TLS (self-signed cert,
//!    fingerprint-pinned by the controller) and every request carries a
//!    pre-shared token compared in constant time.
//!  * Bounded: a fixed command set. Service control is limited to an
//!    allow-list; log tailing to named files; config writes to a store dir.
//!    There is no arbitrary-command / shell capability.

mod config;
mod handlers;
mod server;
mod tls;

#[cfg(windows)]
mod service;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "fleet-agent", version, about = "Overt remote admin agent for your own machines")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a default config, a random token, and a self-signed certificate.
    Init {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print the TLS certificate fingerprint the controller must pin.
    Fingerprint {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run the agent (foreground). With --service it is driven by the Windows
    /// Service Control Manager instead.
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Internal: set by the service installer; hands control to the SCM.
        #[arg(long)]
        service: bool,
    },
    /// Install as a Windows service (requires an elevated prompt).
    Install {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Uninstall the Windows service (requires an elevated prompt).
    Uninstall,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Init { config } => cmd_init(resolve_config(config)),
        Cmd::Fingerprint { config } => cmd_fingerprint(resolve_config(config)),
        Cmd::Run { config, service } => cmd_run(resolve_config(config), service),
        Cmd::Install { config } => cmd_install(resolve_config(config)),
        Cmd::Uninstall => cmd_uninstall(),
    }
}

/// Default config path: %ProgramData%\FleetAgent\config.toml on Windows,
/// a per-user data dir elsewhere (for local development).
pub fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData")
            .unwrap_or_else(|_| "C:\\ProgramData".to_string());
        PathBuf::from(base).join("FleetAgent").join("config.toml")
    }
    #[cfg(not(windows))]
    {
        directories::ProjectDirs::from("", "", "FleetAgent")
            .map(|d| d.data_dir().join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("./fleet-agent-config.toml"))
    }
}

fn resolve_config(opt: Option<PathBuf>) -> PathBuf {
    opt.unwrap_or_else(default_config_path)
}

fn cmd_init(config_path: PathBuf) -> Result<()> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if config_path.exists() {
        println!("Config already exists at {}", config_path.display());
    } else {
        config::AgentConfig::write_example(&config_path)?;
        println!("Wrote example config to {}", config_path.display());
    }

    // Generate a token if one is not already present.
    let token_path = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("token.txt");
    if token_path.exists() {
        println!("Token already exists at {}", token_path.display());
    } else {
        let token = generate_token();
        std::fs::write(&token_path, &token)
            .with_context(|| format!("writing {}", token_path.display()))?;
        restrict_permissions(&token_path);
        println!("Wrote a new random token to {}", token_path.display());
        println!("  (keep this secret; the controller needs the same value)");
    }

    // Generate the certificate and print its fingerprint.
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "localhost".into());
    let paths = tls::CertPaths::next_to(&config_path);
    let fp = tls::ensure_cert(&paths, &hostname)?;
    restrict_permissions(&paths.key);
    println!("\nCertificate fingerprint (pin this in the controller):");
    println!("  {fp}");
    println!("\nNext: review {}, then `fleet-agent install` (elevated).", config_path.display());
    Ok(())
}

fn cmd_fingerprint(config_path: PathBuf) -> Result<()> {
    let paths = tls::CertPaths::next_to(&config_path);
    if !paths.cert.exists() {
        anyhow::bail!(
            "no certificate at {}; run `fleet-agent init` first",
            paths.cert.display()
        );
    }
    println!("{}", tls::fingerprint(&paths.cert)?);
    Ok(())
}

fn cmd_run(config_path: PathBuf, as_service: bool) -> Result<()> {
    if as_service {
        #[cfg(windows)]
        {
            return service::dispatch();
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("--service is only supported on Windows");
        }
    }
    // Foreground run (also used for local testing).
    init_logging(false, &config_path);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(config_path))
}

fn cmd_install(config_path: PathBuf) -> Result<()> {
    #[cfg(windows)]
    {
        if !config_path.exists() {
            anyhow::bail!(
                "config not found at {}; run `fleet-agent init` first",
                config_path.display()
            );
        }
        service::install(&config_path)
    }
    #[cfg(not(windows))]
    {
        let _ = config_path;
        anyhow::bail!("service install is only supported on Windows");
    }
}

fn cmd_uninstall() -> Result<()> {
    #[cfg(windows)]
    {
        service::uninstall()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("service uninstall is only supported on Windows");
    }
}

/// Shared async entry point used by both foreground and service modes.
pub async fn serve(config_path: PathBuf) -> Result<()> {
    // Logging is initialized by the caller (foreground: cmd_run; service:
    // run_service) so the file-vs-stderr choice matches the run mode.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let config = config::AgentConfig::load(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    let token = config::load_token(&config_path)?;

    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "localhost".into());
    let cert_paths = tls::CertPaths::next_to(&config_path);
    let fp = tls::ensure_cert(&cert_paths, &hostname)?;
    tracing::info!(version = VERSION, fingerprint = %fp, "starting fleet-agent");

    let acceptor = tls::build_acceptor(&cert_paths)?;
    let bind = config.bind.clone();
    let ctx = Arc::new(handlers::Context {
        config,
        config_path,
        version: VERSION.to_string(),
    });
    server::run(&bind, acceptor, Arc::new(token), ctx).await
}

/// Set up logging. `from_service` true means also log to a file (SCM processes
/// have no visible console). Returns quietly if a subscriber is already set.
pub(crate) fn init_logging(from_service: bool, config_path: &std::path::Path) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("FLEET_AGENT_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if from_service {
        let log_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("logs");
        std::fs::create_dir_all(&log_dir).ok();
        let log_path = log_dir.join("agent.log");
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_env_filter(filter)
                .with_writer(move || file.try_clone().expect("clone log file handle"))
                .try_init();
            return;
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init();
}

/// Generate a URL-safe random token from the OS RNG via rustls' ring provider.
fn generate_token() -> String {
    use rustls::crypto::ring::default_provider;
    // Pull 32 random bytes and hex-encode them (64 chars).
    let provider = default_provider();
    let mut buf = [0u8; 32];
    provider
        .secure_random
        .fill(&mut buf)
        .expect("OS RNG failed");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Best-effort tighten permissions on secret files (Unix). On Windows the
/// ProgramData ACLs already restrict non-admins; document NTFS hardening.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {}

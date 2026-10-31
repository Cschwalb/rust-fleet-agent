//! Agent configuration: where it binds, which token it accepts, and the
//! allow-lists that bound what the agent will ever do.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Environment variable that overrides the token file. Useful for testing or
/// secret-manager injection; the owner still controls it.
pub const TOKEN_ENV: &str = "FLEET_AGENT_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Address the agent listens on, e.g. "0.0.0.0:7843".
    pub bind: String,

    /// Services the agent is permitted to start/stop/restart. Anything not in
    /// this list is refused, even with a valid token.
    #[serde(default)]
    pub allowed_services: Vec<String>,

    /// Named log files the agent may tail, mapped name -> absolute path.
    /// Only these names are addressable; arbitrary paths are refused.
    #[serde(default)]
    pub logs: BTreeMap<String, String>,

    /// Directory where managed config key/value pairs are stored (one file
    /// per key). Defaults alongside the config file if omitted.
    #[serde(default)]
    pub config_store_dir: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:7843".to_string(),
            allowed_services: Vec::new(),
            logs: BTreeMap::new(),
            config_store_dir: None,
        }
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: AgentConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        Ok(cfg)
    }

    /// Write a commented starter config the owner can edit.
    pub fn write_example(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let example = r#"# fleet-agent configuration
# Address to listen on. Use a specific interface in production rather than
# 0.0.0.0, and keep the port behind your firewall / VPN.
bind = "0.0.0.0:7843"

# Services the agent may start/stop/restart. The agent refuses any service
# name that is not listed here, even with a valid token.
allowed_services = ["Spooler", "W32Time"]

# Named, allow-listed log files the controller may tail by name.
[logs]
agent = "C:\\ProgramData\\FleetAgent\\logs\\agent.log"
# iis = "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\latest.log"

# Where managed config key/value pairs are stored. Defaults to a `store`
# folder next to this config file if omitted.
# config_store_dir = "C:\\ProgramData\\FleetAgent\\store"
"#;
        std::fs::write(path, example)
            .with_context(|| format!("writing example config {}", path.display()))?;
        Ok(())
    }

    pub fn store_dir(&self, config_path: &Path) -> PathBuf {
        match &self.config_store_dir {
            Some(d) => PathBuf::from(d),
            None => config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("store"),
        }
    }
}

/// Resolve the token from the environment first, then a `token.txt` file next
/// to the config. The token is never written to logs.
pub fn load_token(config_path: &Path) -> Result<String> {
    if let Ok(tok) = std::env::var(TOKEN_ENV) {
        let tok = tok.trim().to_string();
        if !tok.is_empty() {
            return Ok(tok);
        }
    }
    let token_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("token.txt");
    let tok = std::fs::read_to_string(&token_path)
        .with_context(|| {
            format!(
                "no token in ${} and could not read {}",
                TOKEN_ENV,
                token_path.display()
            )
        })?
        .trim()
        .to_string();
    if tok.len() < 16 {
        return Err(anyhow!(
            "token in {} is too short ({} chars); use at least 16 random characters",
            token_path.display(),
            tok.len()
        ));
    }
    Ok(tok)
}

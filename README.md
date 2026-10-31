# rust-fleet-agent

An **overt**, authenticated remote administration tool in Rust for machines
**you own**. It has two parts:

- **`fleet-agent`** — runs on each managed Windows box as a normal, visible
  Windows service. It listens on a TLS-encrypted, token-authenticated channel
  and performs a small, fixed set of administrative operations.
- **`fleet-ctl`** — a command-line controller you run from your own machine to
  query and command an agent.

This is deliberately a *fleet management* tool, not a covert one. See
[Design & safety stance](#design--safety-stance).

---

## Design & safety stance

This tool is built for administering computers you own or are authorised to
manage, and it is designed to be obvious about what it is:

- **Overt.** The agent installs as a standard Windows service with a clear name
  (`FleetAgent` / "Fleet Admin Agent") and description. It appears normally in
  `services.msc` and Task Manager. It does **not** hide its process, use
  persistence tricks, tamper with AV/Defender, or obfuscate itself.
- **Authenticated + encrypted.** Every connection is TLS. The agent uses a
  self-signed certificate whose SHA-256 fingerprint the controller pins, and
  every request carries a pre-shared token compared in constant time. A random
  party who reaches the port cannot do anything without the token, and a
  man-in-the-middle with a different certificate is rejected.
- **Bounded by construction.** The agent exposes a *fixed* command set (see
  [Supported commands](#supported-commands)). There is no "run an arbitrary
  command / shell" verb, no keylogging, no screen capture, and no generic file
  exfiltration. Service control is limited to a configured allow-list; log
  tailing to named, allow-listed files; config writes to a dedicated store
  directory.
- **Auditable.** Every authenticated request, every service-control action, and
  every refusal is logged to a visible log file (service mode) or stderr
  (foreground mode).

Keep the control port behind your firewall/VPN, treat the token and private key
as secrets, and only point this at machines you are responsible for.

---

## Workspace layout

```
rust-fleet-agent/
├── common/      # shared wire protocol (commands, responses, TLS framing)
├── agent/       # the service that runs on each managed Windows machine
└── controller/  # the fleet-ctl CLI you run to manage agents
```

---

## Prerequisites

- Rust 1.74+ (`rustup`, stable).
- To **build for Windows**, the simplest path is to build *on* Windows with the
  MSVC toolchain (Visual Studio Build Tools, "Desktop development with C++").
  The crate pins the `ring` crypto provider specifically so no extra C
  libraries are required.

## Building

### On Windows (recommended)

```powershell
# from the rust-fleet-agent directory
rustup target add x86_64-pc-windows-msvc   # usually already the default
cargo build --release
# binaries land in target\release\fleet-agent.exe and fleet-ctl.exe
```

### Cross-compiling from Linux/macOS

`ring` compiles a little C/assembly, so cross-building to Windows needs a
Windows C toolchain. The two tested options:

- **`cargo-xwin`** (uses the MSVC target without a full Visual Studio):
  ```bash
  cargo install cargo-xwin
  rustup target add x86_64-pc-windows-msvc
  cargo xwin build --release --target x86_64-pc-windows-msvc
  ```
- **MinGW** (GNU target): install `mingw-w64`, then
  ```bash
  rustup target add x86_64-pc-windows-gnu
  cargo build --release --target x86_64-pc-windows-gnu
  ```

> The controller (`fleet-ctl`) builds and runs natively on Linux/macOS/Windows,
> so you can drive your Windows fleet from any of them. Only the agent's
> service-install path is Windows-specific; the agent also runs in the
> foreground on any OS for testing (`fleet-agent run`), though service
> enumeration/control only functions on Windows.

---

## Setup on a managed machine

Run these in an **elevated** (Administrator) prompt on the Windows box.

### 1. Initialise config, token, and certificate

```powershell
fleet-agent.exe init
```

This creates, under `%ProgramData%\FleetAgent\`:

- `config.toml` — the agent configuration (edit this; see below).
- `token.txt` — a freshly generated 256-bit random token. **Secret.**
- `cert.pem` / `key.pem` — a self-signed TLS certificate and key.

It prints the **certificate fingerprint** — copy it; the controller needs it.
You can reprint it any time with `fleet-agent.exe fingerprint`.

Pass `--config <path>` to any command to use a non-default location.

### 2. Edit `config.toml`

```toml
# Address to listen on. Prefer a specific interface, behind a firewall/VPN.
bind = "0.0.0.0:7843"

# Services the agent may start/stop/restart. Anything not listed is refused,
# even with a valid token.
allowed_services = ["Spooler", "W32Time"]

# Named, allow-listed log files the controller may tail by name.
[logs]
agent = "C:\\ProgramData\\FleetAgent\\logs\\agent.log"
# iis = "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\latest.log"

# Where managed config key/value pairs are stored.
# Defaults to a `store` folder next to config.toml.
# config_store_dir = "C:\\ProgramData\\FleetAgent\\store"
```

### 3. Harden the secrets (recommended)

Restrict `token.txt` and `key.pem` so only Administrators/SYSTEM can read them:

```powershell
icacls "C:\ProgramData\FleetAgent\token.txt" /inheritance:r /grant:r "SYSTEM:R" "Administrators:R"
icacls "C:\ProgramData\FleetAgent\key.pem"   /inheritance:r /grant:r "SYSTEM:R" "Administrators:R"
```

### 4. Install and start the service

```powershell
fleet-agent.exe install        # registers the "FleetAgent" service (auto-start)
sc start FleetAgent            # or start it from services.msc
```

The service runs as LocalSystem, logs to
`%ProgramData%\FleetAgent\logs\agent.log`, and appears in `services.msc`.

To remove it:

```powershell
fleet-agent.exe uninstall
```

### Credential setup — summary

| Secret        | Where                                    | Set by            |
|---------------|------------------------------------------|-------------------|
| Auth token    | `token.txt` (or `FLEET_AGENT_TOKEN` env) | `init` (random)   |
| TLS key/cert  | `key.pem` / `cert.pem`                   | `init` (self-signed) |
| Fingerprint   | printed by `init` / `fingerprint`        | pin in controller |

To rotate the token, replace `token.txt` (min. 16 chars) and restart the
service. To rotate the certificate, delete `cert.pem`/`key.pem`, run `init`
again, and update the pinned fingerprint in the controller.

---

## Using the controller

Provide the connection details by flag or environment variable:

| Setting      | Flag            | Env var                 |
|--------------|-----------------|-------------------------|
| Agent address| `--host h:port` | `FLEET_CTL_HOST`        |
| Token        | `--token …`     | `FLEET_CTL_TOKEN` (preferred) |
| Fingerprint  | `--fingerprint` | `FLEET_CTL_FINGERPRINT` |

Prefer the env vars for the token so it does not land in your shell history.

```bash
export FLEET_CTL_HOST="winbox.internal:7843"
export FLEET_CTL_TOKEN="…the token from token.txt…"
export FLEET_CTL_FINGERPRINT="23:F8:8A:59:…"   # from `fleet-agent fingerprint`

fleet-ctl ping
fleet-ctl status
fleet-ctl services
fleet-ctl service status Spooler
fleet-ctl service restart Spooler        # must be in allowed_services
fleet-ctl config set maint.window "02:00-04:00"
fleet-ctl config get maint.window
fleet-ctl config list
fleet-ctl tail agent --lines 200
```

Add `--json` to any command for machine-readable output. The controller exits
non-zero when the agent returns an error, so it scripts cleanly.

---

## Supported commands

| Controller command              | What the agent does                                             | Bound by |
|---------------------------------|-----------------------------------------------------------------|----------|
| `ping`                          | Liveness + auth check; returns hostname and agent version.      | token    |
| `status`                        | CPU %, memory, disks, uptime, hostname, OS/kernel.              | token    |
| `services`                      | Lists all Windows services and their state.                     | token    |
| `service status <name>`         | State of one service.                                           | token    |
| `service start\|stop\|restart <name>` | Controls a service.                                       | token **+ `allowed_services`** |
| `config list`                   | Lists managed config keys.                                      | token    |
| `config get <key>`              | Reads one managed config value.                                 | token    |
| `config set <key> <value>`      | Writes one managed config value under the store dir.            | token (keys restricted to `[A-Za-z0-9._-]`) |
| `tail <name> [--lines N]`       | Last N lines of a log.                                          | token **+ `[logs]` allow-list** (N capped at 5000) |

There is intentionally no arbitrary-command, shell, screen, or keystroke
capability. To add an operation you extend the `Command` enum in `common` and
add a matching, bounded handler in `agent` — a deliberate, reviewable change.

---

## Protocol (for reference)

Length-prefixed JSON over TLS: a 4-byte big-endian length, then a JSON body
(capped at 4 MiB). Each connection carries exactly one request and one
response. The request is `{ protocol, token, command }`; the response is
`{ "status": "ok", "payload": … }` or `{ "status": "err", "message": … }`.

## License

MIT.

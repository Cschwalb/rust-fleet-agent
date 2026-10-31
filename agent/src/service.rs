//! Windows service integration. The agent installs as an ordinary, visible
//! Windows service: it appears in services.msc and Task Manager under a clear
//! name and description. There is nothing hidden about it.

#![cfg(windows)]

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "FleetAgent";
pub const SERVICE_DISPLAY: &str = "Fleet Admin Agent";
pub const SERVICE_DESCRIPTION: &str =
    "Overt remote administration agent for machines managed by their owner. \
     Listens on an authenticated, TLS-encrypted control channel.";

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Install the service, pointing it at this executable with the config path.
pub fn install(config_path: &PathBuf) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe = std::env::current_exe().context("resolving current exe path")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("run"),
            OsString::from("--service"),
            OsString::from("--config"),
            config_path.clone().into_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(
        &info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service
        .set_description(SERVICE_DESCRIPTION)
        .context("setting service description")?;
    println!("Installed service '{SERVICE_NAME}' ({SERVICE_DISPLAY}).");
    println!("Start it with:  sc start {SERVICE_NAME}    (or via services.msc)");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    // Best-effort stop before delete.
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    service.delete()?;
    println!("Uninstalled service '{SERVICE_NAME}'.");
    Ok(())
}

/// Hand control to the Windows service dispatcher. Called when the SCM starts
/// the process with `run --service`.
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("starting service dispatcher")?;
    Ok(())
}

// The config path is passed as a launch argument; recover it here.
fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        // At this point logging may not be up; record to the event log via
        // eprintln is not visible, so write to a crash file next to the exe.
        if let Ok(exe) = std::env::current_exe() {
            let crash = exe.with_file_name("fleet-agent-crash.log");
            let _ = std::fs::write(crash, format!("service error: {e:#}\n"));
        }
    }
}

fn run_service(arguments: Vec<OsString>) -> Result<()> {
    let config_path = extract_config_path(&arguments)
        .unwrap_or_else(|| crate::default_config_path());

    // The SCM gives a service process no console, so log to a file.
    crate::init_logging(true, &config_path);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

    let handler_tx = shutdown_tx.clone();
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        use windows_service::service::ServiceControl;
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = handler_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    let running = |state: ServiceState, accept_stop: bool| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if accept_stop {
            windows_service::service::ServiceControlAccept::STOP
                | windows_service::service::ServiceControlAccept::SHUTDOWN
        } else {
            windows_service::service::ServiceControlAccept::empty()
        },
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    status_handle.set_service_status(running(ServiceState::StartPending, false))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    status_handle.set_service_status(running(ServiceState::Running, true))?;

    let result = runtime.block_on(async {
        tokio::select! {
            r = crate::serve(config_path) => r,
            _ = shutdown_rx => {
                tracing::info!("stop requested by SCM");
                Ok(())
            }
        }
    });

    status_handle.set_service_status(running(ServiceState::Stopped, false))?;
    result
}

fn extract_config_path(args: &[OsString]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == "--config" {
            return iter.next().map(PathBuf::from);
        }
    }
    None
}

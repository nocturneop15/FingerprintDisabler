//! install / uninstall / start commands (must run elevated).

use crate::common::*;
use std::{
    ffi::OsString,
    fs,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::System::Registry::*;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

type R<T> = Result<T, String>;

pub fn run(cmd: &str, gui: bool, quiet_success: bool) -> i32 {
    let res = match cmd {
        "install" => install(),
        "uninstall" => uninstall(),
        "start" => start(),
        _ => Err(format!("unknown command {cmd}")),
    };
    let (ok, msg) = match res {
        Ok(m) => (true, m),
        Err(e) => (false, format!("{cmd} failed:\n{e}")),
    };
    if ok { println!("{msg}") } else { eprintln!("{msg}") }
    if gui && !(ok && quiet_success) {
        crate::tray::message_box(&msg, !ok);
    }
    if ok { 0 } else { 1 }
}

fn is_access_denied(e: &windows_service::Error) -> bool {
    matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(5))
}

fn manager() -> R<ServiceManager> {
    ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        if is_access_denied(&e) {
            "Access denied - run this command as Administrator.".to_string()
        } else {
            format!("cannot open service manager: {e}")
        }
    })
}

fn stop_and_wait(svc: &windows_service::service::Service) {
    if let Ok(st) = svc.query_status() {
        if st.current_state != ServiceState::Stopped {
            let _ = svc.stop();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match svc.query_status() {
            Ok(st) if st.current_state == ServiceState::Stopped => return,
            Err(_) => return,
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),
        _ => false,
    }
}

fn copy_exe(src: &Path, dest: &Path) -> R<()> {
    if same_file(src, dest) {
        return Ok(());
    }
    fs::create_dir_all(dest.parent().unwrap()).map_err(|e| format!("create install dir: {e}"))?;
    if dest.exists() && fs::remove_file(dest).is_err() {
        // In use (e.g. tray running from there) - a running exe can be renamed.
        let old = dest.with_extension("exe.old");
        let _ = fs::remove_file(&old);
        fs::rename(dest, &old).map_err(|e| format!("cannot replace {}: {e}", dest.display()))?;
    }
    fs::copy(src, dest).map_err(|e| format!("copy to {}: {e}", dest.display()))?;
    Ok(())
}

fn set_run_key(exe: &Path) -> R<()> {
    let key = wide(RUN_KEY);
    let name = wide(RUN_VALUE_NAME);
    let value = wide(&format!("\"{}\"", exe.display()));
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            REG_SZ,
            value.as_ptr() as _,
            (value.len() * 2) as u32,
        )
    };
    if rc != 0 {
        return Err(format!("cannot write autostart registry value (error {rc})"));
    }
    Ok(())
}

fn delete_run_key() {
    let key = wide(RUN_KEY);
    let name = wide(RUN_VALUE_NAME);
    unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr()) };
}

fn install() -> R<String> {
    let mgr = manager()?;
    let src = std::env::current_exe().map_err(|e| e.to_string())?;
    let dest: PathBuf = install_dir().join(EXE_NAME);

    // Stop an existing instance first so the exe can be replaced.
    let existing = mgr
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)
        .ok();
    if let Some(svc) = &existing {
        stop_and_wait(svc);
    }
    drop(existing);

    copy_exe(&src, &dest)?;

    // Data directory + config writable by normal users (so the non-elevated
    // tray can save settings); everything else stays SYSTEM/admin-only.
    fs::create_dir_all(data_dir()).map_err(|e| format!("create {}: {e}", data_dir().display()))?;
    if !config_path().exists() {
        save_config(&Config::default()).map_err(|e| format!("write config: {e}"))?;
    }
    let out = Command::new("icacls")
        .arg(config_path())
        .args(["/grant", "*S-1-5-32-545:M"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("icacls: {e}"))?;
    if !out.status.success() {
        return Err(format!("icacls failed: {}", String::from_utf8_lossy(&out.stdout)));
    }

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: dest.clone(),
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::STOP;
    let svc = match mgr.open_service(SERVICE_NAME, access) {
        Ok(svc) => {
            svc.change_config(&info).map_err(|e| format!("change service config: {e}"))?;
            svc
        }
        Err(_) => mgr
            .create_service(&info, access)
            .map_err(|e| format!("create service: {e}"))?,
    };
    let _ = svc.set_description(
        "Disables selected biometric devices while the laptop lid is closed (e.g. docked) \
         so Windows Hello falls back to PIN; re-enables them when the lid opens.",
    );
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
            3
        ]),
    });
    svc.start(&[] as &[&str]).map_err(|e| format!("start service: {e}"))?;

    set_run_key(&dest)?;

    Ok(format!(
        "Installed.\n\nService: {SERVICE_NAME} (automatic, LocalSystem)\nProgram: {}\nSettings/log: {}\n\nThe tray icon starts automatically at logon.",
        dest.display(),
        data_dir().display()
    ))
}

fn uninstall() -> R<String> {
    let mgr = manager()?;
    if let Ok(svc) = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        // Stopping re-enables every device the service disabled.
        stop_and_wait(&svc);
        svc.delete().map_err(|e| format!("delete service: {e}"))?;
    }
    delete_run_key();
    let _ = fs::remove_dir_all(data_dir());

    let dest = install_dir().join(EXE_NAME);
    let mut note = String::new();
    if dest.exists() && fs::remove_file(&dest).is_err() {
        // Probably the running tray - delete on next reboot.
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
        let p = wide(&dest.display().to_string());
        unsafe { MoveFileExW(p.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
        note = format!("\n{} is in use and will be removed after reboot.", dest.display());
    } else {
        let _ = fs::remove_file(dest.with_extension("exe.old"));
        let _ = fs::remove_dir(install_dir());
    }
    Ok(format!("Uninstalled. Devices disabled by the service were re-enabled.{note}"))
}

fn start() -> R<String> {
    let mgr = manager()?;
    let svc = mgr
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("open service: {e}"))?;
    svc.start(&[] as &[&str]).map_err(|e| format!("start service: {e}"))?;
    Ok("Service started.".into())
}

/// Service state as seen by a normal (non-elevated) user.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SvcState {
    NotInstalled,
    Stopped,
    Running,
    Pending,
    Unknown,
}

pub fn query_service() -> SvcState {
    let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return SvcState::Unknown;
    };
    match mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => SvcState::NotInstalled,
        Err(_) => SvcState::Unknown,
        Ok(svc) => match svc.query_status().map(|s| s.current_state) {
            Ok(ServiceState::Running) => SvcState::Running,
            Ok(ServiceState::Stopped) => SvcState::Stopped,
            Ok(_) => SvcState::Pending,
            Err(_) => SvcState::Unknown,
        },
    }
}

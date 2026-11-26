//! install / uninstall / start / update commands (must run elevated).

use crate::common::*;
use crate::{devices, trust, updater};
use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::System::Registry::*;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

type R<T> = Result<T, String>;

pub fn run(cmd: &str, args: &[String]) -> i32 {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let value = |f: &str| {
        args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).map(String::as_str)
    };
    let gui = flag("--gui");
    let res = match cmd {
        "install" => install(),
        "uninstall" => uninstall(gui, flag("--force")),
        "start" => start(),
        "update" => update(value("--version")),
        _ => Err(format!("unknown command {cmd}")),
    };
    // The tray reports a successful update itself.
    let quiet_success = flag("--update") || cmd == "update";
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

fn os_error_is(e: &windows_service::Error, code: i32) -> bool {
    matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
}

fn manager() -> R<ServiceManager> {
    ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        if os_error_is(&e, 5) {
            "Access denied - run this command as Administrator.".to_string()
        } else {
            format!("cannot open service manager: {e}")
        }
    })
}

/// Opens the service; `Ok(None)` if it is not installed.
fn open_existing(mgr: &ServiceManager, access: ServiceAccess) -> R<Option<Service>> {
    match mgr.open_service(SERVICE_NAME, access) {
        Ok(svc) => Ok(Some(svc)),
        Err(e) if os_error_is(&e, ERROR_SERVICE_DOES_NOT_EXIST) => Ok(None),
        Err(e) => Err(format!("open service: {e}")),
    }
}

fn is_running(svc: &Service) -> bool {
    svc.query_status().is_ok_and(|s| s.current_state != ServiceState::Stopped)
}

/// Stops the service and waits until the SCM reports it stopped. By then the
/// service has finished re-enabling devices and saved `state.json`.
fn stop_service(svc: &Service) -> R<()> {
    let st = svc.query_status().map_err(|e| format!("query service status: {e}"))?;
    if st.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if st.current_state != ServiceState::StopPending
        && let Err(e) = svc.stop()
        && !os_error_is(&e, ERROR_SERVICE_NOT_ACTIVE)
    {
        return Err(format!("stop service: {e}"));
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        let st = svc.query_status().map_err(|e| format!("query service status: {e}"))?;
        if st.current_state == ServiceState::Stopped {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the service did not stop within {} s (state: {:?})",
                STOP_TIMEOUT.as_secs(),
                st.current_state
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),
        _ => false,
    }
}

fn delete_on_reboot(p: &Path) {
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
    let w = wide(&p.display().to_string());
    unsafe { MoveFileExW(w.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

/// Deletes a file now. If it is in use (e.g. the running tray), it is first
/// renamed to a unique name and only that name is queued for deletion at the
/// next reboot: queuing the original path would delete whatever is installed
/// there by then, e.g. after a reinstall before rebooting.
/// Returns false if the file is still there (pending reboot or stuck).
fn discard(p: &Path) -> bool {
    if !p.exists() || fs::remove_file(p).is_ok() {
        return true;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let trash = p.with_file_name(format!("{name}.{}-{nanos}.delete", std::process::id()));
    if fs::rename(p, &trash).is_ok() {
        delete_on_reboot(&trash);
    }
    false
}

/// `state.json` and quarantined copies of it (`state.json.bad-*`): records
/// of devices that may still need to be re-enabled.
fn is_recovery_record(p: &Path) -> bool {
    p.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|n| n == "state.json" || n.starts_with("state.json.bad-"))
}

/// Quarantined records in the data directory. Any error while scanning is
/// returned rather than treated as "none", so it blocks cleanup.
fn quarantined_records() -> R<Vec<PathBuf>> {
    let it = match fs::read_dir(data_dir()) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot check {} for recovery records: {e}", data_dir().display())),
    };
    let mut out = Vec::new();
    for e in it {
        let p = e.map_err(|e| format!("cannot check {} for recovery records: {e}", data_dir().display()))?.path();
        if is_recovery_record(&p) && p != state_path() {
            out.push(p);
        }
    }
    Ok(out)
}

/// Waits until the service reports Running and is still running shortly
/// after, so an immediate crash is not mistaken for success.
fn wait_running(svc: &Service) -> R<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    let mut running_since: Option<Instant> = None;
    loop {
        let st = svc.query_status().map_err(|e| format!("query service status: {e}"))?;
        match st.current_state {
            ServiceState::Running => {
                let since = *running_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_secs(2) {
                    return Ok(());
                }
            }
            ServiceState::Stopped => {
                return Err(format!(
                    "the service stopped right after starting ({:?}); see {}",
                    st.exit_code,
                    log_path().display()
                ));
            }
            other => {
                running_since = None;
                if Instant::now() >= deadline {
                    return Err(format!("the service did not start within {} s (state: {other:?})", STOP_TIMEOUT.as_secs()));
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// A free name to move the current exe aside to. A previous backup may still
/// be locked by an old tray process, so fall back to numbered names.
fn backup_path(dest: &Path) -> PathBuf {
    (0..100)
        .map(|i| dest.with_extension(if i == 0 { "exe.old".to_string() } else { format!("exe.old{i}") }))
        .find(|b| !b.exists() || fs::remove_file(b).is_ok())
        .unwrap_or_else(|| dest.with_extension(format!("exe.old-{}", std::process::id())))
}

/// Moves the staged exe into place. The current exe is renamed (which works
/// even while it runs) rather than deleted, and is put back if the move
/// fails. Returns the backup path if there was a previous exe.
fn swap_in(staged: &Path, dest: &Path) -> R<Option<PathBuf>> {
    let backup = if dest.exists() {
        let b = backup_path(dest);
        fs::rename(dest, &b).map_err(|e| format!("cannot move {} aside: {e}", dest.display()))?;
        Some(b)
    } else {
        None
    };
    if let Err(e) = fs::rename(staged, dest) {
        let mut msg = format!("cannot move the new program to {}: {e}", dest.display());
        if let Some(b) = &backup {
            match fs::rename(b, dest) {
                Ok(()) => msg.push_str("\n\nThe previous version was kept."),
                Err(r) => msg.push_str(&format!(
                    "\n\nPutting the previous version back also failed ({r}); it is at {}. Reinstall.",
                    b.display()
                )),
            }
        }
        return Err(msg);
    }
    Ok(backup)
}

/// Undoes `swap_in`: the new exe is moved aside and the backup restored.
fn roll_back(dest: &Path, backup: Option<&Path>) -> R<()> {
    if dest.exists() {
        let failed = dest.with_extension("exe.failed");
        discard(&failed);
        fs::rename(dest, &failed).map_err(|e| format!("cannot move the new program aside: {e}"))?;
        discard(&failed);
    }
    if let Some(b) = backup {
        fs::rename(b, dest)
            .map_err(|e| format!("cannot restore {} from {}: {e}", dest.display(), b.display()))?;
    }
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
    let replacing = !same_file(&src, &dest);

    // 1. Stage the new exe next to the old one before anything is stopped,
    //    so a failed copy leaves the current installation untouched.
    fs::create_dir_all(install_dir()).map_err(|e| format!("create install dir: {e}"))?;
    let staged = dest.with_extension("exe.new");
    if replacing {
        let _ = fs::remove_file(&staged);
        if let Err(e) = fs::copy(&src, &staged) {
            let _ = fs::remove_file(&staged);
            return Err(format!("copy to {}: {e}", staged.display()));
        }
    }

    // 2. Stop the running service and confirm that it stopped.
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START;
    let existing = open_existing(&mgr, access).inspect_err(|_| {
        let _ = fs::remove_file(&staged);
    })?;
    let was_running = existing.as_ref().is_some_and(is_running);
    if let Some(svc) = &existing
        && let Err(e) = stop_service(svc)
    {
        let _ = fs::remove_file(&staged);
        return Err(format!("{e}\n\nNothing was changed."));
    }
    // Restarts the previous service if it was running; appends the outcome.
    let restart_old = |msg: &mut String| {
        if let (true, Some(svc)) = (was_running, &existing) {
            let res = svc
                .start(&[] as &[&str])
                .map_err(|e| format!("start service: {e}"))
                .and_then(|()| wait_running(svc));
            match res {
                Ok(()) => msg.push_str("\nThe service is running again."),
                Err(e) => msg.push_str(&format!("\nRestarting the service also failed: {e}")),
            }
        }
    };

    // 3. Swap the exe.
    let backup = if replacing {
        match swap_in(&staged, &dest) {
            Ok(b) => b,
            Err(mut e) => {
                discard(&staged);
                restart_old(&mut e);
                return Err(e);
            }
        }
    } else {
        None
    };

    // 4. Configure, start and confirm it runs; roll the exe back on failure.
    //    The backup is only deleted once the new service is confirmed running.
    match configure_and_start(&mgr, &dest) {
        Ok(msg) => {
            if let Some(b) = &backup {
                discard(b);
            }
            Ok(msg)
        }
        Err(e) if !replacing => Err(e),
        Err(e) => {
            let mut msg = e;
            // The new version may have started (and then failed); it must be
            // stopped before the old one can run again.
            let stopped = match open_existing(&mgr, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP) {
                Ok(Some(svc)) => stop_service(&svc),
                Ok(None) => Ok(()),
                Err(e) => Err(e),
            };
            if let Err(s) = &stopped {
                // Swapping files under a service Windows still reports as
                // running is unsafe: leave both versions where they are.
                msg.push_str(&format!("\n\nStopping the new version failed: {s}"));
                if let Some(b) = &backup {
                    msg.push_str(&format!(
                        "\nIt was left in place; the previous version is kept at {}.",
                        b.display()
                    ));
                }
                return Err(msg);
            }
            match roll_back(&dest, backup.as_deref()) {
                Ok(()) if backup.is_some() => msg.push_str("\n\nThe previous version was restored."),
                Ok(()) => {}
                Err(r) => msg.push_str(&format!("\n\nRestoring the previous version failed: {r}")),
            }
            if existing.is_none() {
                // First install: don't leave a service pointing at nothing.
                if let Ok(Some(svc)) = open_existing(&mgr, ServiceAccess::DELETE) {
                    let _ = svc.delete();
                }
                delete_run_key();
            } else {
                restart_old(&mut msg);
            }
            Err(msg)
        }
    }
}

fn configure_and_start(mgr: &ServiceManager, dest: &Path) -> R<String> {
    // Establish the trusted data directory (and config.json, the only file
    // normal users may write) before the service is started.
    let _dir = trust::trusted_data_dir()?;

    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: dest.to_path_buf(),
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::STOP;
    let svc = match open_existing(mgr, access)? {
        Some(svc) => {
            svc.change_config(&info).map_err(|e| format!("change service config: {e}"))?;
            svc
        }
        None => mgr
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
    set_run_key(dest)?;
    // Last, so nothing after it can fail and leave the new version running
    // while the old one gets restored.
    svc.start(&[] as &[&str]).map_err(|e| format!("start service: {e}"))?;
    // A successful start request only means Windows launched the process.
    wait_running(&svc)?;

    Ok(format!(
        "Installed.\n\nService: {SERVICE_NAME} (automatic, LocalSystem)\nProgram: {}\nSettings/log: {}\n\nThe tray icon starts automatically at logon.",
        dest.display(),
        data_dir().display()
    ))
}

/// Re-enables devices still listed in `state.json` (the service may not have
/// managed to, e.g. after a crash or because a device was unplugged),
/// updates the record and returns the devices that are still unresolved.
fn restore_owned_devices() -> R<Vec<String>> {
    let mut st = load_state().map_err(|e| format!("cannot read {}: {e}", state_path().display()))?;
    if st.owned.is_empty() {
        return Ok(Vec::new());
    }
    let devs = devices::enumerate().map_err(|e| format!("device enumeration failed: {e}"))?;
    let restart_msg = |name: &str, id: &str| format!("{name} [{id}]: re-enabled, but Windows must restart to finish");
    let mut pending = st.reboot_pending.clone();
    let mut remaining = Vec::new();
    let mut unresolved = Vec::new();
    for id in &st.owned {
        let key = pending.keys().find(|k| k.eq_ignore_ascii_case(id)).cloned();
        let restart_recorded = key.as_ref().and_then(|k| pending.get(k)).is_some_and(BootMarker::restart_outstanding);
        let mut keep = |msg: String| {
            unresolved.push(msg);
            remaining.push(id.clone());
        };
        match devs.iter().find(|d| d.instance_id.eq_ignore_ascii_case(id)) {
            None => keep(format!("{id} (not present)")),
            Some(d) if !d.status_known => keep(format!("{} [{id}]: Windows cannot report its status", d.name)),
            Some(d) if d.problem == devices::CM_PROB_NEED_RESTART => keep(restart_msg(&d.name, id)),
            // Re-enabled in this boot but only effective after a restart
            // (recorded by the service or an earlier uninstall attempt).
            Some(d) if d.disabled && restart_recorded => keep(restart_msg(&d.name, id)),
            Some(d) if !d.disabled => {
                if let Some(k) = &key {
                    pending.remove(k);
                }
            }
            Some(d) => match devices::set_enabled(&d.instance_id, true) {
                Ok(false) => {
                    if let Some(k) = &key {
                        pending.remove(k);
                    }
                }
                // Not confirmed until after the restart: record that, so the
                // service and later uninstall attempts know it too.
                Ok(true) => {
                    pending.insert(key.clone().unwrap_or_else(|| id.clone()), BootMarker::current());
                    keep(restart_msg(&d.name, id));
                }
                Err(e) => keep(format!("{} [{id}]: {e}", d.name)),
            },
        }
    }
    pending.retain(|k, _| remaining.iter().any(|r| r.eq_ignore_ascii_case(k)));
    if remaining != st.owned || pending != st.reboot_pending {
        st.owned = remaining;
        st.reboot_pending = pending;
        save_state(&st).map_err(|e| format!("cannot update {}: {e}", state_path().display()))?;
    }
    Ok(unresolved)
}

fn uninstall(gui: bool, force: bool) -> R<String> {
    let mgr = manager()?;
    let svc = open_existing(
        &mgr,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START | ServiceAccess::DELETE,
    )?;
    // Stopping re-enables every device the service disabled. It must really
    // have stopped before the recovery record is checked.
    if let Some(svc) = &svc {
        stop_service(svc).map_err(|e| format!("{e}\n\nNothing was removed."))?;
    }

    // Records are only read, and the directory only cleaned, once it is
    // established as trusted.
    let dir = trust::trusted_data_dir();
    let mut unresolved = Vec::new();
    match &dir {
        Ok(_) => {
            unresolved.extend(restore_owned_devices().unwrap_or_else(|e| vec![e]));
            // A record the service had to quarantine as corrupt can't be
            // checked, so it may still list disabled devices.
            match quarantined_records() {
                Ok(qs) => unresolved.extend(qs.iter().map(|q| {
                    format!("unreadable earlier record {} (devices listed there may still be disabled)", q.display())
                })),
                Err(e) => unresolved.push(e),
            }
        }
        Err(e) => unresolved.push(format!("cannot verify {}: {e}", data_dir().display())),
    }
    // Untrusted directories moved aside with records in them.
    match trust::review_dirs() {
        Ok(ds) => unresolved.extend(ds.iter().map(|d| {
            format!("unverified earlier records kept in {} (devices listed there may still be disabled)", d.display())
        })),
        Err(e) => unresolved.push(e),
    }
    let keep_state = !unresolved.is_empty();
    if keep_state {
        let list = unresolved.join("\n");
        let proceed = force
            || (gui
                && crate::tray::ask_yes_no(&format!(
                    "These devices were disabled by Fingerprint Disabler and are not confirmed re-enabled:\n\n{list}\n\n\
                     Uninstall anyway? Restart Windows or enable them in Device Manager yourself.\n\n\
                     Choose No to keep the service, which re-enables them as soon as it can."
                )));
        if !proceed {
            if let Some(svc) = &svc {
                let _ = svc.start(&[] as &[&str]);
            }
            return Err(format!(
                "these devices disabled by the service are not confirmed re-enabled:\n{list}\n\n\
                 The service was left installed and restarted so it can re-enable them later.\n\
                 To remove it anyway, run `uninstall --force` (the records are kept)."
            ));
        }
    }

    if let Some(svc) = svc {
        svc.delete().map_err(|e| format!("delete service: {e}"))?;
    }
    delete_run_key();
    match dir {
        // Untrusted: leave it untouched.
        Err(_) => {}
        Ok(_) if keep_state => {
            // Keep the recovery records (and the trust marker); remove the rest.
            if let Ok(entries) = fs::read_dir(data_dir()) {
                for e in entries.flatten() {
                    if !is_recovery_record(&e.path()) && !trust::is_marker(&e.path()) {
                        let _ = fs::remove_file(e.path());
                    }
                }
            }
        }
        Ok(handle) => {
            drop(handle);
            let _ = fs::remove_dir_all(data_dir());
        }
    }
    if !keep_state {
        trust::delete_boot_key();
    }

    // Program files, including leftover .old/.new copies. Anything in use
    // (probably the running tray) is renamed and deleted at the next reboot.
    let mut in_use = false;
    if let Ok(entries) = fs::read_dir(install_dir()) {
        for e in entries.flatten() {
            in_use |= !discard(&e.path());
        }
    }
    if in_use {
        // Only removed at reboot if it is empty by then, so a reinstall in
        // the meantime is not affected.
        delete_on_reboot(&install_dir());
    } else {
        let _ = fs::remove_dir(install_dir());
    }

    let mut msg = if keep_state {
        format!(
            "Uninstalled, but these devices are not confirmed re-enabled - restart Windows or enable them in Device Manager:\n{}\n\nThe records were kept.",
            unresolved.join("\n")
        )
    } else {
        "Uninstalled. Devices disabled by the service were re-enabled.".to_string()
    };
    if in_use {
        msg.push_str(&format!(
            "\n\nSome files in {} are in use and will be removed after reboot.",
            install_dir().display()
        ));
    }
    Ok(msg)
}

fn start() -> R<String> {
    let mgr = manager()?;
    let svc = mgr
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| format!("open service: {e}"))?;
    svc.start(&[] as &[&str]).map_err(|e| format!("start service: {e}"))?;
    Ok("Service started.".into())
}

/// Elevated self-update. Everything that decides what runs with admin rights
/// happens in this process: the release is looked up, downloaded, SHA-256
/// verified and written into the admin-only install directory, and only that
/// copy is executed. Nothing written by the non-elevated tray is used.
fn update(expected_version: Option<&str>) -> R<String> {
    let info = updater::check()?
        .ok_or_else(|| format!("no release newer than {} is available", updater::VERSION))?;
    if let Some(v) = expected_version
        && v != info.version
    {
        return Err(format!(
            "the latest release is now {}, not {v} as offered. Check for updates again.",
            info.version
        ));
    }
    let data = updater::fetch_verified(&info)?;

    let dir = install_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let staged = dir.join("fingerprint-disabler.update.exe");
    discard(&staged);
    let write = || -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&staged)?;
        f.write_all(&data)?;
        f.sync_all()
    };
    write().map_err(|e| format!("write {}: {e}", staged.display()))?;

    let result = (|| {
        // Verify what is actually on disk, then run exactly that file.
        let on_disk = fs::read(&staged).map_err(|e| format!("read {}: {e}", staged.display()))?;
        updater::verify(&on_disk, &info.sha256)?;
        let out = Command::new(&staged)
            .args(["install", "--update"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("cannot run the new version: {e}"))?;
        if out.status.success() {
            Ok(format!("Updated to {}.", info.version))
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.trim().trim_start_matches("install failed:").trim();
            Err(if err.is_empty() { format!("the installer exited with {}", out.status) } else { err.to_string() })
        }
    })();
    discard(&staged);
    result
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

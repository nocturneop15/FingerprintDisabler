//! The Windows service (runs as LocalSystem) and the enforcement worker.
//!
//! Lid state comes from the GUID_LIDSWITCH_STATE_CHANGE power notification,
//! which Windows delivers immediately on registration (current state) and on
//! every change. The worker wakes up instantly on a lid event and additionally
//! every `poll_interval_ms` to reload the config and re-enforce device state
//! (e.g. if Windows or a driver update re-enabled a device while docked).

use crate::common::*;
use crate::devices::{self, CM_PROB_NEED_RESTART};
use crate::trust;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    os::windows::io::AsRawHandle,
    sync::{
        Mutex, OnceLock,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    time::{Duration, SystemTime},
};
use windows_service::{
    define_windows_service,
    service::{
        LidSwitchStateChange, PowerBroadcastSetting, PowerEventParam, ServiceControl,
        ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::System::Power::{
    RegisterPowerSettingNotification, UnregisterPowerSettingNotification,
};
use windows_sys::Win32::System::SystemServices::GUID_LIDSWITCH_STATE_CHANGE;
use windows_sys::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_SERVICE_HANDLE;

pub enum Event {
    /// Stop the worker. `restore` re-enables all devices the service disabled.
    Stop { restore: bool },
    Lid { closed: bool },
    /// Re-check now (resume from sleep etc.).
    Poke,
}

// ---------------------------------------------------------------- service --

define_windows_service!(ffi_service_main, service_main);

pub fn run_service() {
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        log(format!("service dispatcher failed: {e}"));
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_as_service() {
        log(format!("service error: {e}"));
    }
}

fn run_as_service() -> windows_service::Result<()> {
    let (tx, rx) = mpsc::channel::<Event>();

    let handler = move |ctrl: ServiceControl| -> ServiceControlHandlerResult {
        match ctrl {
            ServiceControl::Stop => {
                let _ = tx.send(Event::Stop { restore: true });
                ServiceControlHandlerResult::NoError
            }
            // On shutdown keep the current state: if the machine boots docked
            // the fingerprint reader is already off at the lock screen; if it
            // boots with lid open, the initial lid notification re-enables it.
            ServiceControl::Shutdown => {
                let _ = tx.send(Event::Stop { restore: false });
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::PowerEvent(PowerEventParam::PowerSettingChange(
                PowerBroadcastSetting::LidSwitchStateChange(s),
            )) => {
                let _ = tx.send(Event::Lid { closed: s == LidSwitchStateChange::Closed });
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(
                PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend,
            ) => {
                let _ = tx.send(Event::Poke);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(_) => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    // Nothing is read, written or changed (no log file, no devices) unless
    // the data directory is trusted. Held open for the service's lifetime.
    let _dir = match trust::trusted_data_dir() {
        Ok(d) => d,
        Err(e) => {
            trust::report_error(&format!("Fingerprint Disabler service not started: {e}"));
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return Ok(());
        }
    };
    let set_state = |state: ServiceState, accept: ServiceControlAccept| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };

    set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::POWER_EVENT,
    );

    let notify = unsafe {
        RegisterPowerSettingNotification(
            status_handle.as_raw_handle() as _,
            &GUID_LIDSWITCH_STATE_CHANGE,
            DEVICE_NOTIFY_SERVICE_HANDLE,
        )
    };
    if notify == 0 {
        log(format!("RegisterPowerSettingNotification failed: {}", std::io::Error::last_os_error()));
    }

    log("service started");
    worker(rx);

    if notify != 0 {
        unsafe { UnregisterPowerSettingNotification(notify) };
    }
    set_state(ServiceState::Stopped, ServiceControlAccept::empty());
    log("service stopped");
    Ok(())
}

// --------------------------------------------------------------- console --

static CONSOLE_TX: OnceLock<Mutex<Sender<Event>>> = OnceLock::new();

fn console_send(ev: Event) {
    if let Some(tx) = CONSOLE_TX.get() {
        let _ = tx.lock().unwrap().send(ev);
    }
}

/// Runs the worker in the foreground (for testing; needs an elevated prompt).
/// Lid events are received through a hidden window instead of the SCM.
pub fn run_console() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    let _dir = match trust::trusted_data_dir() {
        Ok(d) => d,
        Err(e) => {
            trust::report_error(&format!("Not started: {e}"));
            return;
        }
    };
    let (tx, rx) = mpsc::channel::<Event>();
    let _ = CONSOLE_TX.set(Mutex::new(tx));

    unsafe extern "system" fn ctrl_handler(_ctrl: u32) -> i32 {
        console_send(Event::Stop { restore: true });
        1
    }
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };

    std::thread::spawn(lid_window_thread);
    log("console mode started (Ctrl+C to stop and restore devices)");
    worker(rx);
    log("console mode stopped");
}

fn lid_window_thread() {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::POWERBROADCAST_SETTING;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe {
            if msg == WM_POWERBROADCAST {
                if wp as u32 == PBT_POWERSETTINGCHANGE {
                    let s = &*(lp as *const POWERBROADCAST_SETTING);
                    if guid_eq(&s.PowerSetting, &GUID_LIDSWITCH_STATE_CHANGE) && s.DataLength >= 4 {
                        let v = *(s.Data.as_ptr() as *const u32);
                        console_send(Event::Lid { closed: v == 0 });
                    }
                } else if wp as u32 == PBT_APMRESUMEAUTOMATIC || wp as u32 == PBT_APMRESUMESUSPEND {
                    console_send(Event::Poke);
                }
                return 1;
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
    }

    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let cls = wide("FingerprintDisablerConsoleLid");
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.lpszClassName = cls.as_ptr();
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            0, cls.as_ptr(), cls.as_ptr(), 0, 0, 0, 0, 0,
            std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null(),
        );
        RegisterPowerSettingNotification(hwnd, &GUID_LIDSWITCH_STATE_CHANGE, DEVICE_NOTIFY_WINDOW_HANDLE);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

fn guid_eq(a: &windows_sys::core::GUID, b: &windows_sys::core::GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

// ---------------------------------------------------------------- worker --

fn config_mtime() -> Option<SystemTime> {
    std::fs::metadata(config_path()).and_then(|m| m.modified()).ok()
}

struct Worker {
    cfg: Config,
    cfg_mtime: Option<SystemTime>,
    /// What `state.json` currently holds. Only valid when `state_loaded`.
    state: State,
    state_loaded: bool,
    /// Owned devices whose re-enable Windows completes only after a restart
    /// -> boot in which that was reported. Persisted in `state.json`.
    reboot_pending: BTreeMap<String, BootMarker>,
    lid_closed: Option<bool>,
    /// Last error per device, so repeated failures are logged once.
    errors: HashMap<String, String>,
    last_status: Option<Status>,
    /// Instance ID (upper case) -> friendly name, refreshed on every enumeration.
    names: HashMap<String, String>,
}

fn worker(rx: Receiver<Event>) {
    let mut w = Worker {
        cfg: load_config(),
        cfg_mtime: config_mtime(),
        state: State::default(),
        state_loaded: false,
        reboot_pending: BTreeMap::new(),
        lid_closed: None,
        errors: HashMap::new(),
        last_status: None,
        names: HashMap::new(),
    };
    log(format!(
        "config: enabled={}, poll={} ms, devices={:?}",
        w.cfg.enabled, w.cfg.poll_ms(), w.cfg.devices
    ));

    loop {
        let timeout = Duration::from_millis(w.cfg.poll_ms());
        match rx.recv_timeout(timeout) {
            Ok(Event::Stop { restore }) => {
                if restore {
                    log("stopping: re-enabling devices disabled by this service");
                    if w.ensure_state() {
                        w.reconcile(&BTreeSet::new());
                    }
                    if !w.state.owned.is_empty() {
                        log(format!(
                            "stopped with devices still disabled (kept in state.json for recovery): {:?}",
                            w.state.owned
                        ));
                    }
                } else {
                    log("system shutdown: keeping current device state");
                }
                w.publish(false);
                return;
            }
            Ok(Event::Lid { closed }) => {
                if w.lid_closed != Some(closed) {
                    log(format!("lid {}", if closed { "CLOSED" } else { "OPEN" }));
                }
                w.lid_closed = Some(closed);
            }
            Ok(Event::Poke) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        w.tick();
    }
}

impl Worker {
    fn tick(&mut self) {
        let mtime = config_mtime();
        if mtime != self.cfg_mtime {
            self.cfg_mtime = mtime;
            let cfg = load_config();
            if cfg != self.cfg {
                log(format!(
                    "config reloaded: enabled={}, poll={} ms, devices={:?}",
                    cfg.enabled, cfg.poll_ms(), cfg.devices
                ));
                self.cfg = cfg;
            }
        }

        // Ownership record unreadable: touching devices could lose track of
        // them, so wait until it can be read.
        if !self.ensure_state() {
            self.publish(true);
            return;
        }
        match self.lid_closed {
            // Lid state not known yet: don't touch anything.
            None => {}
            Some(closed) => {
                let desired: BTreeSet<String> = if closed && self.cfg.enabled {
                    self.cfg.devices.iter().map(|s| s.to_uppercase()).collect()
                } else {
                    BTreeSet::new()
                };
                self.reconcile(&desired);
            }
        }
        self.publish(true);
    }

    /// Loads `state.json` once. Returns false while it cannot be read (the
    /// caller must not touch devices then). A corrupt file is moved aside so
    /// its contents stay available for manual recovery.
    fn ensure_state(&mut self) -> bool {
        if self.state_loaded {
            return true;
        }
        match load_state() {
            Ok(st) => {
                self.reboot_pending = st.reboot_pending.iter().map(|(k, v)| (k.to_uppercase(), v.clone())).collect();
                self.state = st;
                self.state_loaded = true;
                self.errors.remove("state");
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                let secs = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let bad = state_path().with_extension(format!("json.bad-{secs}"));
                if let Err(m) = std::fs::rename(state_path(), &bad) {
                    // Carrying on would let the next save overwrite the only
                    // copy of the record, so stay hands-off until it is moved.
                    self.note_error(
                        "state",
                        format!("state.json is corrupt ({e}) and cannot be moved aside ({m}); not changing any device"),
                    );
                    return false;
                }
                self.note_error(
                    "state",
                    format!(
                        "state.json was corrupt ({e}); kept as {} - devices listed there may need to be re-enabled in Device Manager",
                        bad.display()
                    ),
                );
                self.state = State::default();
                self.state_loaded = true;
                true
            }
            Err(e) => {
                self.note_error("state", format!("cannot read state.json ({e}); not changing any device until it can be read"));
                false
            }
        }
    }

    /// Writes the ownership set to `state.json` if it changed.
    fn persist(&mut self, owned: &BTreeSet<String>) -> std::io::Result<()> {
        let st = State {
            owned: owned.iter().cloned().collect(),
            reboot_pending: self
                .reboot_pending
                .iter()
                .filter(|(id, _)| owned.contains(*id))
                .map(|(id, b)| (id.clone(), b.clone()))
                .collect(),
        };
        if st == self.state {
            return Ok(());
        }
        save_state(&st)?;
        self.state = st;
        Ok(())
    }

    /// Makes the devices in `desired` disabled; re-enables every device the
    /// service disabled earlier that is not in `desired`.
    ///
    /// Ownership is recorded durably *before* a device is disabled, so a
    /// crash or failed write can never leave a disabled device that the
    /// service does not know it has to re-enable.
    fn reconcile(&mut self, desired: &BTreeSet<String>) {
        let devs = match devices::enumerate() {
            Ok(d) => d,
            Err(e) => {
                self.note_error("enumerate", format!("device enumeration failed: {e}"));
                return;
            }
        };
        self.errors.remove("enumerate");
        self.names = devs.iter().map(|d| (d.instance_id.to_uppercase(), d.name.clone())).collect();
        let mut owned: BTreeSet<String> = self.state.owned.iter().map(|s| s.to_uppercase()).collect();

        for d in &devs {
            let id = d.instance_id.to_uppercase();
            if !d.status_known {
                // Can't tell whether it is enabled: change nothing, and keep
                // any ownership record as it is.
                self.note_error(&id, format!("cannot read the status of '{}'; leaving it alone", d.name));
                continue;
            }
            if desired.contains(&id) {
                if !d.disabled {
                    if owned.insert(id.clone())
                        && let Err(e) = self.persist(&owned)
                    {
                        owned.remove(&id);
                        self.note_error(&id, format!("not disabling '{}': cannot save state.json: {e}", d.name));
                        continue;
                    }
                    self.reboot_pending.remove(&id);
                    match devices::set_enabled(&d.instance_id, false) {
                        Ok(reboot) => {
                            log(format!("disabled '{}' [{}]{}", d.name, d.instance_id,
                                if reboot { " (reboot required!)" } else { "" }));
                            self.errors.remove(&id);
                        }
                        // Stays owned: if the disable partly took effect it
                        // still gets re-enabled; if not, the next pass drops it.
                        Err(e) => self.note_error(&id, format!("cannot disable '{}': {e}", d.name)),
                    }
                }
            } else if owned.contains(&id) {
                let restart_pending = self.reboot_pending.get(&id).is_some_and(BootMarker::restart_outstanding)
                    || d.problem == CM_PROB_NEED_RESTART;
                if restart_pending && (d.disabled || d.problem == CM_PROB_NEED_RESTART) {
                    // Enabled, but Windows finishes it only after a restart:
                    // keep the record until the device is really back.
                    self.note_error(&id, format!("Windows must restart to finish re-enabling '{}'", d.name));
                } else if d.disabled {
                    match devices::set_enabled(&d.instance_id, true) {
                        Ok(false) => {
                            log(format!("enabled '{}' [{}]", d.name, d.instance_id));
                            owned.remove(&id);
                            self.errors.remove(&id);
                        }
                        Ok(true) => {
                            log(format!("enabled '{}' [{}] (Windows restart required to finish)", d.name, d.instance_id));
                            self.reboot_pending.insert(id.clone(), BootMarker::current());
                            self.note_error(&id, format!("Windows must restart to finish re-enabling '{}'", d.name));
                        }
                        Err(e) => self.note_error(&id, format!("cannot enable '{}': {e}", d.name)),
                    }
                } else {
                    // Working again (re-enabled by someone else, or the
                    // restart happened).
                    owned.remove(&id);
                    self.reboot_pending.remove(&id);
                    self.errors.remove(&id);
                }
            }
        }
        // Owned devices that are not present (unplugged) stay in the set so
        // they get re-enabled when they show up again.

        // Only removals are left to save here; if this fails the on-disk
        // record still lists them and the next pass retries.
        match self.persist(&owned) {
            Ok(()) => {
                self.errors.remove("state-save");
            }
            Err(e) => self.note_error("state-save", format!("cannot save state.json: {e}")),
        }
    }

    fn note_error(&mut self, key: &str, msg: String) {
        if self.errors.get(key) != Some(&msg) {
            log(&msg);
            self.errors.insert(key.to_string(), msg);
        }
    }

    fn publish(&mut self, running: bool) {
        let names = &self.names;
        let status = Status {
            lid: match self.lid_closed {
                Some(true) => "closed",
                Some(false) => "open",
                None => "unknown",
            }
            .into(),
            enabled: self.cfg.enabled,
            disabled: self
                .state
                .owned
                .iter()
                .map(|id| DeviceRef {
                    id: id.clone(),
                    name: names.get(&id.to_uppercase()).cloned().unwrap_or_else(|| id.clone()),
                })
                .collect(),
            errors: self.errors.values().cloned().collect(),
            running,
        };
        if self.last_status.as_ref() != Some(&status) {
            if let Ok(json) = serde_json::to_string_pretty(&status) {
                let _ = write_atomic(&status_path(), json.as_bytes());
            }
            self.last_status = Some(status);
        }
    }
}

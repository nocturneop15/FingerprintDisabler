//! Shared paths, config/status files, logging and small Win32 helpers.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const SERVICE_NAME: &str = "FingerprintDisabler";
pub const SERVICE_DISPLAY_NAME: &str = "Fingerprint Disabler (lid aware)";
pub const RUN_VALUE_NAME: &str = "FingerprintDisablerTray";
pub const EXE_NAME: &str = "fingerprint-disabler.exe";

pub const MIN_POLL_MS: u64 = 100;
pub const MAX_POLL_MS: u64 = 60_000;

/// Resolves a Windows known folder. Deliberately not read from environment
/// variables (`%ProgramFiles%` etc.): those come from the calling user and
/// are inherited by elevated processes, so they must not decide where an
/// admin process reads, writes or what it runs.
fn known_folder(id: &windows_sys::core::GUID, fallback: &str) -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut p) };
    let res = if hr >= 0 && !p.is_null() {
        let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        let s = std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(p, len) });
        Some(PathBuf::from(s))
    } else {
        None
    };
    unsafe { CoTaskMemFree(p as _) };
    res.unwrap_or_else(|| PathBuf::from(fallback))
}

pub fn data_dir() -> PathBuf {
    use windows_sys::Win32::UI::Shell::FOLDERID_ProgramData;
    known_folder(&FOLDERID_ProgramData, "C:\\ProgramData").join("FingerprintDisabler")
}
pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}
pub fn status_path() -> PathBuf {
    data_dir().join("status.json")
}
pub fn state_path() -> PathBuf {
    data_dir().join("state.json")
}
pub fn log_path() -> PathBuf {
    data_dir().join("service.log")
}
pub fn install_dir() -> PathBuf {
    use windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles;
    known_folder(&FOLDERID_ProgramFiles, "C:\\Program Files").join("FingerprintDisabler")
}

/// The installed exe, but only if its real location (after resolving
/// junctions and symlinks) is exactly `install_dir()\EXE_NAME`. Used before
/// running it with administrator rights.
pub fn verified_installed_exe() -> Result<PathBuf, String> {
    let expected = install_dir().join(EXE_NAME);
    let real = fs::canonicalize(&expected).map_err(|e| format!("{}: {e}", expected.display()))?;
    let real_s = real.to_string_lossy();
    let real_s = real_s.strip_prefix(r"\\?\").unwrap_or(&real_s);
    if !real_s.eq_ignore_ascii_case(&expected.to_string_lossy()) {
        return Err(format!("{} resolves to {real_s}, outside the install folder", expected.display()));
    }
    let meta = fs::symlink_metadata(&expected).map_err(|e| format!("{}: {e}", expected.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", expected.display()));
    }
    Ok(expected)
}

/// User settings. Written by the tray app, read by the service.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Master switch.
    pub enabled: bool,
    /// How often the service re-checks / enforces device state.
    pub poll_interval_ms: u64,
    /// Device instance IDs to disable while the lid is closed.
    pub devices: Vec<String>,
    /// Check GitHub releases for a newer version (tray app).
    pub check_updates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { enabled: true, poll_interval_ms: 500, devices: Vec::new(), check_updates: true }
    }
}

impl Config {
    pub fn poll_ms(&self) -> u64 {
        self.poll_interval_ms.clamp(MIN_POLL_MS, MAX_POLL_MS)
    }
}

pub fn load_config() -> Config {
    fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config(cfg: &Config) -> io::Result<()> {
    // Write in place (truncate) so the file keeps the ACL set by the installer.
    let json = serde_json::to_string_pretty(cfg).map_err(io::Error::other)?;
    fs::write(config_path(), json)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct DeviceRef {
    pub id: String,
    pub name: String,
}

/// Runtime status published by the service for the tray.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Status {
    /// "open", "closed" or "unknown"
    pub lid: String,
    pub enabled: bool,
    /// Devices currently disabled by the service.
    pub disabled: Vec<DeviceRef>,
    pub errors: Vec<String>,
    pub running: bool,
}

pub fn load_status() -> Option<Status> {
    fs::read_to_string(status_path()).ok().and_then(|s| serde_json::from_str(&s).ok())
}

/// Devices the service itself disabled (persisted so that they get re-enabled
/// even after a crash / reboot, but devices disabled manually by the user are
/// never touched).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct State {
    pub owned: Vec<String>,
    /// Owned devices whose re-enable Windows only completes after a restart,
    /// mapped to the boot session in which that was reported. Shared by the
    /// service and the uninstaller.
    pub reboot_pending: std::collections::BTreeMap<String, BootMarker>,
}

/// Which Windows boot session reported that a restart is required.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum BootMarker {
    /// `trust::boot_session_id()` at the time.
    Session(String),
    /// The session could not be determined (or a legacy timestamp record).
    Unverifiable(u64),
}

impl BootMarker {
    pub fn current() -> Self {
        crate::trust::boot_session_id().map_or(BootMarker::Unverifiable(0), BootMarker::Session)
    }

    /// True while the required restart has not provably happened. Only an
    /// exact session ID that differs from the current one proves a restart;
    /// anything unverifiable keeps the record until the device is confirmed
    /// working.
    pub fn restart_outstanding(&self) -> bool {
        self.outstanding_given(crate::trust::boot_session_id().as_deref())
    }

    pub fn outstanding_given(&self, current: Option<&str>) -> bool {
        match (self, current) {
            (BootMarker::Session(id), Some(cur)) => id == cur,
            _ => true,
        }
    }
}

/// Reads `state.json`. A missing file is an empty state; any other read or
/// parse failure is an error, because treating it as empty would forget
/// devices that still need to be re-enabled.
pub fn load_state() -> io::Result<State> {
    match fs::read_to_string(state_path()) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e),
    }
}

/// Durably replaces `state.json` (write temp file, flush, atomic rename), so
/// a crash or power loss leaves either the old or the new record, never a
/// truncated one.
pub fn save_state(st: &State) -> io::Result<()> {
    let json = serde_json::to_string_pretty(st).map_err(io::Error::other)?;
    write_atomic(&state_path(), json.as_bytes())
}

pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    let (from, to) = (wide(&tmp.display().to_string()), wide(&path.display().to_string()));
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        let e = io::Error::last_os_error();
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

pub fn timestamp() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let t = unsafe {
        let mut t = std::mem::zeroed();
        GetLocalTime(&mut t);
        t
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds
    )
}

/// Appends a line to the service log (rotated at ~1 MB) and echoes it to stderr.
static FILE_LOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enables writing the log file; see `trust::trusted_data_dir`.
pub fn set_file_log(on: bool) {
    FILE_LOG.store(on, std::sync::atomic::Ordering::SeqCst);
}

pub fn log(msg: impl AsRef<str>) {
    let line = format!("{} {}\n", timestamp(), msg.as_ref());
    eprint!("{line}");
    // Only once the data directory has been established as trusted.
    if !FILE_LOG.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let path = log_path();
    if fs::metadata(&path).map(|m| m.len() > 1_000_000).unwrap_or(false) {
        let _ = fs::rename(&path, path.with_extension("log.old"));
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_marker_only_a_different_session_proves_a_restart() {
        let m = BootMarker::Session("abc".into());
        // Service restart: same volatile ID -> restart still outstanding.
        assert!(m.outstanding_given(Some("abc")));
        // Windows restart: the volatile key was recreated with a new ID.
        assert!(!m.outstanding_given(Some("def")));
        // ID unavailable, or nothing to compare: keep the record.
        assert!(m.outstanding_given(None));
        assert!(BootMarker::Unverifiable(0).outstanding_given(Some("def")));
    }

    #[test]
    fn state_round_trips_and_older_formats_load() {
        let mut st = State { owned: vec!["X".into()], ..Default::default() };
        st.reboot_pending.insert("X".into(), BootMarker::Session("0123".into()));
        let back: State = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
        assert_eq!(back, st);
        let old: State = serde_json::from_str(r#"{"owned":["Y"]}"#).unwrap();
        assert!(old.reboot_pending.is_empty());
        // Timestamp markers from the previous build are kept, as unverifiable.
        let ts: State = serde_json::from_str(r#"{"owned":["Y"],"reboot_pending":{"Y":1764000000}}"#).unwrap();
        assert_eq!(ts.reboot_pending["Y"], BootMarker::Unverifiable(1764000000));
    }
}

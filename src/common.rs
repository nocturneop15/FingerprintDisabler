//! Shared paths, config/status files, logging and small Win32 helpers.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

pub const SERVICE_NAME: &str = "FingerprintDisabler";
pub const SERVICE_DISPLAY_NAME: &str = "Fingerprint Disabler (lid aware)";
pub const RUN_VALUE_NAME: &str = "FingerprintDisablerTray";
pub const EXE_NAME: &str = "fingerprint-disabler.exe";

pub const MIN_POLL_MS: u64 = 100;
pub const MAX_POLL_MS: u64 = 60_000;

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
    PathBuf::from(base).join("FingerprintDisabler")
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
    let base = std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
    PathBuf::from(base).join("FingerprintDisabler")
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
}

pub fn load_state() -> State {
    fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_state(st: &State) {
    if let Ok(json) = serde_json::to_string_pretty(st) {
        let _ = fs::write(state_path(), json);
    }
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
pub fn log(msg: impl AsRef<str>) {
    let line = format!("{} {}\n", timestamp(), msg.as_ref());
    eprint!("{line}");
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

//! Trust boundary for privileged code (installer, LocalSystem service).
//!
//! * The data directory is only used once it is established as trusted: a
//!   real directory (not a junction/link), owned by SYSTEM or Administrators,
//!   with a protected DACL in which no other account has any right beyond
//!   read/execute, and containing a marker file only this code creates.
//!   Anything else is moved aside (its records kept for review) and a fresh
//!   directory is created with its final security descriptor. The directory
//!   handle is kept open without delete sharing, so it cannot be renamed or
//!   swapped while in use.
//! * The boot session ID is a random value in a volatile HKLM key: Windows
//!   discards it on restart, so "has Windows restarted since X?" is an exact
//!   comparison instead of a clock estimate.

use crate::common::*;
use std::{
    fs,
    io::{self, Read, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::Mutex,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

/// SYSTEM and Administrators: full control; Users: read/execute. Protected
/// (no inheritance from ProgramData, which lets users add files). The owner
/// is the creating token's default owner (Administrators or SYSTEM).
const DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// As above, plus Users may read and write the contents (not delete it or
/// change its permissions), so the non-elevated tray can save settings.
const CONFIG_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;BU)";
/// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
const READ_EXECUTE: u32 = 0x0012_00a9;
/// Created right after the directory, so only directories created by this
/// code (never one secured after the fact) are adopted.
const MARKER: &str = ".secured-v1";
pub const REVIEW_PREFIX: &str = "FingerprintDisabler.review-";
const ERROR_ALREADY_EXISTS: i32 = 183;

/// An open handle to the trusted data directory. While it exists the
/// directory cannot be renamed or deleted.
pub struct TrustedDir {
    _handle: OwnedHandle,
}

/// Establishes the trusted data directory (creating it if needed) and turns
/// on file logging. Must run elevated / as SYSTEM. Nothing in the directory
/// may be read or written by privileged code unless this succeeded.
pub fn trusted_data_dir() -> Result<TrustedDir, String> {
    let path = data_dir();
    let mut carried_config: Option<Config> = None;
    for _ in 0..3 {
        match create_dir_secured(&path) {
            Ok(()) => {
                let h = open_dir(&path)?;
                check_dir(&h).map_err(|e| format!("new directory {}: {e}", path.display()))?;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join(MARKER))
                    .map_err(|e| format!("create {}: {e}", path.join(MARKER).display()))?;
                ensure_config(carried_config.take().unwrap_or_default())?;
                set_file_log(true);
                return Ok(TrustedDir { _handle: h });
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS) => {}
            Err(e) => return Err(format!("create {}: {e}", path.display())),
        }

        let reason = match open_dir(&path) {
            Ok(h) => match check_dir(&h) {
                Ok(()) if is_plain_file(&path.join(MARKER)) => {
                    ensure_config(carried_config.take().unwrap_or_default())?;
                    set_file_log(true);
                    return Ok(TrustedDir { _handle: h });
                }
                Ok(()) => "it was secured after creation, so earlier contents are unverified".to_string(),
                Err(e) => e,
            },
            Err(e) => e,
        };
        // Release our handle so it can be moved.
        let cfg = move_aside(&path, &reason)?;
        carried_config = carried_config.or(cfg);
    }
    Err(format!("{} keeps being re-created by another account", path.display()))
}

/// Directories moved aside because they could not be trusted and held
/// recovery records. Errors while scanning are returned, not ignored.
pub fn review_dirs() -> Result<Vec<PathBuf>, String> {
    let parent = data_dir().parent().map(Path::to_path_buf).unwrap_or_default();
    let err = |e: io::Error| format!("cannot check {} for kept records: {e}", parent.display());
    let mut out = Vec::new();
    for e in fs::read_dir(&parent).map_err(err)? {
        let e = e.map_err(err)?;
        if e.file_name().to_string_lossy().starts_with(REVIEW_PREFIX) {
            out.push(e.path());
        }
    }
    Ok(out)
}

/// Whether `name` is the trust marker (kept when the directory is cleaned).
pub fn is_marker(p: &Path) -> bool {
    p.file_name().is_some_and(|n| n == MARKER)
}

// ------------------------------------------------------------- directory --

struct LocalMem(*mut core::ffi::c_void);
impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn security_descriptor(sddl: &str) -> io::Result<LocalMem> {
    let s = wide(sddl);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), SDDL_REVISION_1, &mut sd, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalMem(sd))
}

fn create_dir_secured(path: &Path) -> io::Result<()> {
    let sd = security_descriptor(DIR_SDDL)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let p = wide(&path.display().to_string());
    if unsafe { CreateDirectoryW(p.as_ptr(), &sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens the directory itself (never what a junction points to), without
/// delete sharing, and checks that it is a plain directory.
fn open_dir(path: &Path) -> Result<OwnedHandle, String> {
    let p = wide(&path.display().to_string());
    let h: HANDLE = unsafe {
        CreateFileW(
            p.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("open {}: {}", path.display(), io::Error::last_os_error()));
    }
    let h = unsafe { OwnedHandle::from_raw_handle(h) };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(h.as_raw_handle(), &mut info) } == 0 {
        return Err(format!("query {}: {}", path.display(), io::Error::last_os_error()));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("it is a junction or link".into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err("it is not a directory".into());
    }
    Ok(h)
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> [u8; SECURITY_MAX_SID_SIZE as usize] {
    let mut buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = buf.len() as u32;
    unsafe { CreateWellKnownSid(kind, ptr::null_mut(), buf.as_mut_ptr() as PSID, &mut len) };
    buf
}

fn sid_string(sid: PSID) -> String {
    let mut s = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return "an unknown account".into();
    }
    let _free = LocalMem(s as _);
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) })
}

/// Checks owner and DACL of an open file/directory: owner SYSTEM or
/// Administrators, DACL protected, and no allow entry granting any other
/// account more than read/execute (this includes inherit-only entries,
/// which would grant it on new files).
fn check_dir(h: &OwnedHandle) -> Result<(), String> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            h.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(format!("cannot read its permissions: {}", io::Error::from_raw_os_error(rc as i32)));
    }
    let _free = LocalMem(sd);

    let sy = well_known_sid(WinLocalSystemSid);
    let ba = well_known_sid(WinBuiltinAdministratorsSid);
    let privileged = |sid: PSID| unsafe {
        EqualSid(sid, sy.as_ptr() as PSID) != 0 || EqualSid(sid, ba.as_ptr() as PSID) != 0
    };

    let (mut control, mut rev) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut rev) } == 0 {
        return Err(format!("cannot read its permissions: {}", io::Error::last_os_error()));
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err("it inherits permissions from its parent, which lets users add files".into());
    }
    if dacl.is_null() {
        return Err("it has no access list, so everyone has full access".into());
    }
    for i in 0..unsafe { (*dacl).AceCount } as u32 {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
            return Err(format!("cannot read its permissions: {}", io::Error::last_os_error()));
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        match header.AceType as u32 {
            ACCESS_DENIED_ACE_TYPE => {}
            ACCESS_ALLOWED_ACE_TYPE => {
                let a = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                let sid = &a.SidStart as *const u32 as PSID;
                if !privileged(sid) && a.Mask & !READ_EXECUTE != 0 {
                    return Err(format!("it grants {} more than read access (0x{:x})", sid_string(sid), a.Mask));
                }
            }
            t => return Err(format!("it has an unsupported access entry (type {t})")),
        }
    }
    if owner.is_null() || !privileged(owner) {
        return Err(format!("it is owned by {}", if owner.is_null() { "nobody".into() } else { sid_string(owner) }));
    }
    Ok(())
}

fn is_plain_file(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| {
        use std::os::windows::fs::MetadataExt;
        m.is_file() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    })
}

/// Creates `config.json` with its own DACL if it does not exist. The
/// directory is trusted at this point, so an existing file was created here.
fn ensure_config(cfg: Config) -> Result<(), String> {
    let path = config_path();
    if fs::symlink_metadata(&path).is_ok() {
        return Ok(());
    }
    let sd = security_descriptor(CONFIG_SDDL).map_err(|e| format!("config permissions: {e}"))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let p = wide(&path.display().to_string());
    const GENERIC_WRITE: u32 = 0x4000_0000;
    let h = unsafe {
        CreateFileW(p.as_ptr(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, ptr::null_mut())
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("create {}: {}", path.display(), io::Error::last_os_error()));
    }
    let mut f = unsafe { fs::File::from_raw_handle(h) };
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    f.write_all(json.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Reads at most `cap` bytes of a file, refusing links / reparse points.
fn read_untrusted(p: &Path, cap: u64) -> Option<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(p)
        .ok()?;
    {
        use std::os::windows::fs::MetadataExt;
        let m = f.metadata().ok()?;
        if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return None;
        }
    }
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Moves an untrusted directory out of the way. If it may hold recovery
/// records, it is kept as `FingerprintDisabler.review-*` for review (they
/// are never used automatically); otherwise it is deleted. Returns the
/// user's settings from it, parsed (only known fields), to carry over.
fn move_aside(path: &Path, reason: &str) -> Result<Option<Config>, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let aside = path.with_file_name(format!("{REVIEW_PREFIX}{nanos}"));
    fs::rename(path, &aside).map_err(|e| {
        format!(
            "{} cannot be trusted ({reason}) and cannot be moved aside: {e}. Close programs using it and retry.",
            path.display()
        )
    })?;

    let link = fs::symlink_metadata(&aside).is_ok_and(|m| {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    });
    if link {
        // Removes the junction itself, not its target.
        let _ = fs::remove_dir(&aside);
        report_error(&format!("Removed {} ({reason}).", path.display()));
        return Ok(None);
    }

    let cfg = read_untrusted(&aside.join("config.json"), 64 * 1024)
        .and_then(|b| serde_json::from_slice::<Config>(&b).ok());
    let state_file = aside.join("state.json");
    let has_records = match read_untrusted(&state_file, 1024 * 1024) {
        Some(b) => serde_json::from_slice::<State>(&b).map_or(true, |st| !st.owned.is_empty()),
        None => fs::symlink_metadata(&state_file).is_ok(),
    } || fs::read_dir(&aside).map_or(true, |it| {
        it.flatten().any(|e| e.file_name().to_string_lossy().starts_with("state.json.bad-"))
    });
    if has_records {
        report_error(&format!(
            "{} could not be trusted ({reason}). It was moved to {}; devices listed in its records may need to be re-enabled in Device Manager.",
            path.display(),
            aside.display()
        ));
    } else {
        // Does not follow links inside it.
        let _ = fs::remove_dir_all(&aside);
    }
    Ok(cfg)
}

// ------------------------------------------------------------- event log --

/// Reports an error to stderr and the Windows Application event log (used
/// when the data directory, and so the log file, cannot be trusted).
pub fn report_error(msg: &str) {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };
    eprintln!("{msg}");
    let src = wide(SERVICE_NAME);
    let text = wide(msg);
    unsafe {
        let h = RegisterEventSourceW(ptr::null(), src.as_ptr());
        if !h.is_null() {
            let strings = [text.as_ptr()];
            ReportEventW(h, EVENTLOG_ERROR_TYPE, 0, 1, ptr::null_mut(), 1, 0, strings.as_ptr(), ptr::null());
            DeregisterEventSource(h);
        }
    }
}

// ---------------------------------------------------------- boot session --

pub const BOOT_KEY: &str = "SOFTWARE\\FingerprintDisabler-BootSession";

/// Random ID of the current Windows boot session, shared by all processes
/// (service, installer). Kept in a volatile HKLM key, which Windows discards
/// on restart. Fast Startup resumes the previous kernel session and keeps
/// it, which matches device changes (they too wait for a real restart).
/// `None` if it cannot be read or created (needs admin rights).
pub fn boot_session_id() -> Option<String> {
    static CACHE: Mutex<Option<String>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.is_none() {
        *cache = read_or_create_boot_id();
    }
    cache.clone()
}

fn read_or_create_boot_id() -> Option<String> {
    use windows_sys::Win32::System::Registry::*;
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    // Serialize first-time creation between processes.
    let name = wide("Global\\FingerprintDisablerBootSession");
    let m = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    if m.is_null() {
        return None;
    }
    let w = unsafe { WaitForSingleObject(m, 10_000) };
    if w != WAIT_OBJECT_0 && w != WAIT_ABANDONED {
        unsafe { CloseHandle(m) };
        return None;
    }
    let id = unsafe {
        let key = wide(BOOT_KEY);
        let mut hk: HKEY = ptr::null_mut();
        let mut disp = 0;
        let rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            ptr::null(),
            &mut hk,
            &mut disp,
        );
        if rc != 0 {
            None
        } else {
            let val = wide("Id");
            let mut buf = [0u16; 64];
            let mut cb = (buf.len() * 2) as u32;
            let rc = RegGetValueW(hk, ptr::null(), val.as_ptr(), RRF_RT_REG_SZ, ptr::null_mut(), buf.as_mut_ptr() as _, &mut cb);
            let id = if rc == 0 {
                Some(from_wide(&buf))
            } else {
                random_hex().and_then(|id| {
                    let w = wide(&id);
                    (RegSetValueExW(hk, val.as_ptr(), 0, REG_SZ, w.as_ptr() as _, (w.len() * 2) as u32) == 0).then_some(id)
                })
            };
            RegCloseKey(hk);
            id.filter(|s| s.len() >= 32)
        }
    };
    unsafe {
        ReleaseMutex(m);
        CloseHandle(m);
    }
    id
}

fn random_hex() -> Option<String> {
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
    let mut b = [0u8; 16];
    let st = unsafe { BCryptGenRandom(ptr::null_mut(), b.as_mut_ptr(), b.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    (st == 0).then(|| b.iter().map(|x| format!("{x:02x}")).collect())
}

pub fn delete_boot_key() {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegDeleteKeyW};
    let key = wide(BOOT_KEY);
    unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, key.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a directory with the given SDDL (owner: the test user).
    fn dir_with(name: &str, sddl: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fpd-trust-{}-{name}", std::process::id()));
        let sd = security_descriptor(sddl).unwrap();
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let w = wide(&p.display().to_string());
        assert_ne!(unsafe { CreateDirectoryW(w.as_ptr(), &sa) }, 0, "{}", io::Error::last_os_error());
        p
    }

    fn cleanup(p: &Path) {
        // As owner we may always rewrite the DACL; open it up, then delete.
        let _ = std::process::Command::new("icacls").arg(p).args(["/reset"]).output();
        let _ = fs::remove_dir_all(p);
    }

    fn verdict(p: &Path) -> Result<(), String> {
        check_dir(&open_dir(p)?)
    }

    #[test]
    fn rejects_explicit_write_grant_to_other_accounts() {
        // What `icacls /inheritance:r /grant:r` left behind: protected DACL,
        // but an extra explicit Authenticated Users: Modify entry.
        let p = dir_with("au", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1301bf;;;AU)");
        let v = verdict(&p);
        cleanup(&p);
        let e = v.unwrap_err();
        assert!(e.contains("S-1-5-11") && e.contains("more than read"), "{e}");
    }

    #[test]
    fn rejects_inherited_dacl() {
        let p = std::env::temp_dir().join(format!("fpd-trust-{}-inh", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        let v = verdict(&p);
        let _ = fs::remove_dir_all(&p);
        assert!(v.unwrap_err().contains("inherits"));
    }

    #[test]
    fn rejects_owner_other_than_system_or_admins() {
        // Correct DACL, but created (owned) by this non-admin test user.
        let p = dir_with("own", DIR_SDDL);
        let v = verdict(&p);
        cleanup(&p);
        let e = v.unwrap_err();
        // Running elevated, the owner is Administrators and this passes.
        if !e.contains("owned by") {
            panic!("{e}");
        }
    }

    #[test]
    fn config_descriptor_lets_users_save_settings() {
        // The test user is in Users; that entry is its only write grant.
        let p = std::env::temp_dir().join(format!("fpd-trust-{}-cfg.json", std::process::id()));
        let sd = security_descriptor(CONFIG_SDDL).unwrap();
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let w = wide(&p.display().to_string());
        const GENERIC_WRITE: u32 = 0x4000_0000;
        let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, ptr::null_mut()) };
        assert_ne!(h, INVALID_HANDLE_VALUE);
        drop(unsafe { fs::File::from_raw_handle(h) });
        // What the tray's save_config does (truncate + write in place).
        let res = fs::write(&p, b"{}");
        let read = fs::read(&p);
        let _ = std::process::Command::new("icacls").arg(&p).arg("/reset").output();
        let _ = fs::remove_file(&p);
        res.unwrap();
        assert_eq!(read.unwrap(), b"{}");
    }

    #[test]
    fn rejects_junction() {
        let base = std::env::temp_dir().join(format!("fpd-trust-{}-jt", std::process::id()));
        let target = base.with_extension("target");
        fs::create_dir_all(&target).unwrap();
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&base)
            .arg(&target)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok);
        let v = open_dir(&base).map(|_| ());
        fs::remove_dir(&base).unwrap();
        fs::remove_dir_all(&target).unwrap();
        assert!(v.unwrap_err().contains("junction"));
    }
}

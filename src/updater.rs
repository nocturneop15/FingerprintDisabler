//! Update check against GitHub releases (WinHTTP + BCrypt SHA-256, no extra deps).
//!
//! The latest release must contain an asset named `fingerprint-disabler.exe`.
//! GitHub publishes a `sha256:` digest for every release asset; the downloaded
//! file must match it before it is executed.

use crate::common::{EXE_NAME, wide};
use serde::Deserialize;
use std::{path::PathBuf, ptr};
use windows_sys::Win32::Networking::WinHttp::*;

pub const REPO: &str = "nocturneop15/FingerprintDisabler";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct UpdateInfo {
    pub version: String,
    pub asset_url: String,
    /// Expected SHA-256 (lower-case hex).
    pub sha256: String,
    pub html_url: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

/// Parses "v1.2.3" / "1.2.3" (pre-release suffixes ignored).
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>());
    let major = it.next()?.ok()?;
    let minor = it.next().unwrap_or(Ok(0)).ok()?;
    let patch = it.next().unwrap_or(Ok(0)).ok()?;
    Some((major, minor, patch))
}

/// Returns `Ok(Some(..))` when a newer release is available.
pub fn check() -> Result<Option<UpdateInfo>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = http_get(&url, Some("Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28"))?;
    let rel: Release = serde_json::from_slice(&body).map_err(|e| format!("bad release JSON: {e}"))?;
    if rel.draft || rel.prerelease {
        return Ok(None);
    }
    let latest = parse_version(&rel.tag_name).ok_or_else(|| format!("bad tag {}", rel.tag_name))?;
    let current = parse_version(VERSION).unwrap_or((0, 0, 0));
    if latest <= current {
        return Ok(None);
    }
    let asset = rel
        .assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(EXE_NAME))
        .ok_or_else(|| format!("release {} has no {EXE_NAME} asset", rel.tag_name))?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|d| d.strip_prefix("sha256:"))
        .map(|d| d.to_ascii_lowercase())
        .ok_or_else(|| "release asset has no SHA-256 digest".to_string())?;
    Ok(Some(UpdateInfo {
        version: rel.tag_name.trim_start_matches(['v', 'V']).to_string(),
        asset_url: asset.browser_download_url.clone(),
        sha256,
        html_url: rel.html_url,
    }))
}

/// Downloads and verifies the update; returns the path of the new exe.
pub fn download(info: &UpdateInfo) -> Result<PathBuf, String> {
    let data = http_get(&info.asset_url, None)?;
    let actual = sha256_hex(&data)?;
    if actual != info.sha256 {
        return Err(format!("checksum mismatch (expected {}, got {actual})", info.sha256));
    }
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let dir = base.join("FingerprintDisabler").join("update");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("fingerprint-disabler-{}.exe", info.version));
    std::fs::write(&path, &data).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

fn sha256_hex(data: &[u8]) -> Result<String, String> {
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};
    let mut out = [0u8; 32];
    let st = unsafe {
        BCryptHash(BCRYPT_SHA256_ALG_HANDLE, ptr::null(), 0, data.as_ptr(), data.len() as u32, out.as_mut_ptr(), 32)
    };
    if st != 0 {
        return Err(format!("BCryptHash failed: 0x{st:08x}"));
    }
    Ok(out.iter().map(|b| format!("{b:02x}")).collect())
}

struct H(*mut core::ffi::c_void);
impl Drop for H {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn last_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Minimal HTTPS GET (follows redirects, uses system proxy settings).
fn http_get(url: &str, headers: Option<&str>) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("https://").ok_or("only https URLs are supported")?;
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = if path.is_empty() { "/" } else { path };

    unsafe {
        let agent = wide(&format!("FingerprintDisabler-Updater/{VERSION}"));
        let session = H(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, ptr::null(), ptr::null(), 0));
        if session.0.is_null() {
            return Err(last_err("WinHttpOpen"));
        }
        WinHttpSetTimeouts(session.0, 10_000, 10_000, 30_000, 60_000);

        let host_w = wide(host);
        let conn = H(WinHttpConnect(session.0, host_w.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT as u16, 0));
        if conn.0.is_null() {
            return Err(last_err("WinHttpConnect"));
        }
        let verb = wide("GET");
        let path_w = wide(path);
        let req = H(WinHttpOpenRequest(
            conn.0, verb.as_ptr(), path_w.as_ptr(), ptr::null(), ptr::null(), ptr::null(), WINHTTP_FLAG_SECURE,
        ));
        if req.0.is_null() {
            return Err(last_err("WinHttpOpenRequest"));
        }
        let hdr = headers.map(wide);
        let (hp, hl) = match &hdr {
            Some(h) => (h.as_ptr(), u32::MAX), // -1 = null terminated
            None => (ptr::null(), 0),
        };
        if WinHttpSendRequest(req.0, hp, hl, ptr::null(), 0, 0, 0) == 0 {
            return Err(last_err("connection failed"));
        }
        if WinHttpReceiveResponse(req.0, ptr::null_mut()) == 0 {
            return Err(last_err("no response"));
        }
        let mut status = 0u32;
        let mut len = 4u32;
        WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            &mut status as *mut u32 as _,
            &mut len,
            ptr::null_mut(),
        );

        let mut body = Vec::new();
        loop {
            let mut avail = 0u32;
            if WinHttpQueryDataAvailable(req.0, &mut avail) == 0 {
                return Err(last_err("read failed"));
            }
            if avail == 0 {
                break;
            }
            let start = body.len();
            body.resize(start + avail as usize, 0);
            let mut read = 0u32;
            if WinHttpReadData(req.0, body[start..].as_mut_ptr() as _, avail, &mut read) == 0 {
                return Err(last_err("read failed"));
            }
            body.truncate(start + read as usize);
            if body.len() > 64 * 1024 * 1024 {
                return Err("response too large".into());
            }
        }
        match status {
            200 => Ok(body),
            404 => Err("no published release found".into()),
            s => Err(format!("HTTP {s} from {host}")),
        }
    }
}

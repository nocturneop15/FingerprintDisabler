//! System tray icon + settings window (runs non-elevated in the user session).

use crate::common::*;
use crate::devices;
use crate::install::{SvcState, query_service};
use crate::updater::{self, UpdateInfo, VERSION};
use std::{
    cell::{Cell, RefCell},
    mem, ptr,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{CreateMutexW, INFINITE, WaitForSingleObject, GetExitCodeProcess};
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const WM_REFRESH: u32 = WM_APP + 2;
const WM_UPDATE: u32 = WM_APP + 3;
const TIMER_ID: usize = 1;
const UPDATE_TIMER_ID: usize = 2;
const UPDATE_FIRST_DELAY_MS: u32 = 15_000;
const UPDATE_PERIOD_MS: u32 = 24 * 60 * 60 * 1000;
const NIN_BALLOONUSERCLICK: u32 = WM_USER + 5;
const TRAY_UID: u32 = 1;

const IDM_SETTINGS: usize = 100;
const IDM_TOGGLE: usize = 101;
const IDM_INSTALL: usize = 102;
const IDM_UNINSTALL: usize = 103;
const IDM_START: usize = 104;
const IDM_LOG: usize = 105;
const IDM_EXIT: usize = 106;
const IDM_CHECK_UPDATE: usize = 107;
const IDM_UPDATE: usize = 108;
const IDM_RELEASES: usize = 109;

// settings window control IDs (IDOK / IDCANCEL give Enter / Esc handling)
const IDC_LIST: i32 = 200;
const IDC_ACTIVE: i32 = 201;
const IDC_INTERVAL: i32 = 202;
const IDC_REFRESH: i32 = 203;
const IDC_UPDATES: i32 = 204;

const ICON_NORMAL: u16 = 1;
const ICON_ACTIVE: u16 = 2;
const ICON_PAUSED: u16 = 3;

thread_local! {
    static MAIN_HWND: Cell<HWND> = const { Cell::new(ptr::null_mut()) };
    static SETTINGS_HWND: Cell<HWND> = const { Cell::new(ptr::null_mut()) };
    static TASKBAR_CREATED: Cell<u32> = const { Cell::new(0) };
    static CURRENT: RefCell<(u16, String)> = const { RefCell::new((0, String::new())) };
    static FONT: Cell<HFONT> = const { Cell::new(ptr::null_mut()) };
    static LIST_IDS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static MUTEX: Cell<HANDLE> = const { Cell::new(ptr::null_mut()) };
    static UPDATE: RefCell<Option<UpdateInfo>> = const { RefCell::new(None) };
    static UPDATE_BUSY: Cell<bool> = const { Cell::new(false) };
}

/// Results of background update work, posted to the tray window.
enum UpdateMsg {
    Found { info: UpdateInfo, manual: bool },
    UpToDate { manual: bool },
    CheckFailed { err: String, manual: bool },
    Installed,
    InstallFailed(Option<String>),
}

fn post_update(msg: UpdateMsg, hwnd: isize) {
    let p = Box::into_raw(Box::new(msg));
    unsafe {
        if PostMessageW(hwnd as HWND, WM_UPDATE, 0, p as LPARAM) == 0 {
            drop(Box::from_raw(p));
        }
    }
}

fn hinstance() -> HINSTANCE {
    unsafe { GetModuleHandleW(ptr::null()) }
}

fn load_icon(id: u16, small: bool) -> HICON {
    unsafe {
        let (cx, cy) = if small {
            (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON))
        } else {
            (GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON))
        };
        LoadImageW(hinstance(), id as usize as *const u16, IMAGE_ICON, cx, cy, LR_SHARED) as HICON
    }
}

pub fn message_box(text: &str, error: bool) {
    let t = wide(text);
    let c = wide("Fingerprint Disabler");
    let flags = if error { MB_ICONERROR } else { MB_ICONINFORMATION };
    unsafe { MessageBoxW(ptr::null_mut(), t.as_ptr(), c.as_ptr(), flags | MB_OK | MB_SETFOREGROUND) };
}

pub fn ask_yes_no(text: &str) -> bool {
    let t = wide(text);
    let c = wide("Fingerprint Disabler");
    let flags = MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND;
    unsafe { MessageBoxW(ptr::null_mut(), t.as_ptr(), c.as_ptr(), flags) == IDYES }
}

// --------------------------------------------------------------- startup --

pub fn run(updated: bool) {
    unsafe {
        // Single instance per session.
        let name = wide("Local\\FingerprintDisablerTray");
        let mutex = CreateMutexW(ptr::null(), 0, name.as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return;
        }
        MUTEX.set(mutex);

        enable_visual_styles();
        windows_sys::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(
            windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
        );

        let icc = INITCOMMONCONTROLSEX {
            dwSize: mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES,
        };
        InitCommonControlsEx(&icc);

        // UI font
        let mut ncm: NONCLIENTMETRICSW = mem::zeroed();
        ncm.cbSize = mem::size_of::<NONCLIENTMETRICSW>() as u32;
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &mut ncm as *mut _ as _, 0);
        FONT.set(CreateFontIndirectW(&ncm.lfMessageFont));

        let cls = wide("FingerprintDisablerTray");
        let mut wc: WNDCLASSW = mem::zeroed();
        wc.lpfnWndProc = Some(main_proc);
        wc.hInstance = hinstance();
        wc.lpszClassName = cls.as_ptr();
        RegisterClassW(&wc);

        let scls = wide("FingerprintDisablerSettings");
        let mut wc: WNDCLASSW = mem::zeroed();
        wc.lpfnWndProc = Some(settings_proc);
        wc.hInstance = hinstance();
        wc.lpszClassName = scls.as_ptr();
        wc.hCursor = LoadCursorW(ptr::null_mut(), IDC_ARROW);
        wc.hbrBackground = (COLOR_BTNFACE + 1) as usize as HBRUSH;
        wc.hIcon = load_icon(ICON_NORMAL, false);
        RegisterClassW(&wc);

        // Hidden top-level window (not message-only so it gets TaskbarCreated).
        let hwnd = CreateWindowExW(
            0, cls.as_ptr(), cls.as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0,
            ptr::null_mut(), ptr::null_mut(), hinstance(), ptr::null(),
        );
        MAIN_HWND.set(hwnd);
        TASKBAR_CREATED.set(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()));

        add_tray_icon(hwnd);
        refresh();
        SetTimer(hwnd, TIMER_ID, 1000, None);
        SetTimer(hwnd, UPDATE_TIMER_ID, UPDATE_FIRST_DELAY_MS, None);
        if updated {
            balloon("Fingerprint Disabler updated", &format!("Now running version {VERSION}."));
        }

        // First run without the service: point the user at it.
        if query_service() == SvcState::NotInstalled {
            open_settings();
        }

        let mut msg: MSG = mem::zeroed();
        while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
            let s = SETTINGS_HWND.get();
            if !s.is_null() && IsDialogMessageW(s, &msg) != 0 {
                continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let mut nid = nid_base(hwnd);
        Shell_NotifyIconW(NIM_DELETE, &mut nid);
    }
}

/// Activates the embedded common-controls v6 manifest (resource ID 2) for the
/// lifetime of the process, giving the settings window modern Windows 11 controls.
fn enable_visual_styles() {
    use windows_sys::Win32::System::ApplicationInstallationAndServicing::*;
    unsafe {
        let mut ctx: ACTCTXW = mem::zeroed();
        ctx.cbSize = mem::size_of::<ACTCTXW>() as u32;
        ctx.dwFlags = 0x80 | 0x08; // ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID
        ctx.hModule = hinstance();
        ctx.lpResourceName = 2 as *const u16;
        let h = CreateActCtxW(&ctx);
        if h as isize != -1 {
            let mut cookie = 0usize;
            ActivateActCtx(h, &mut cookie);
        }
    }
}

fn nid_base(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut nid: NOTIFYICONDATAW = unsafe { mem::zeroed() };
    nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    nid
}

fn add_tray_icon(hwnd: HWND) {
    let mut nid = nid_base(hwnd);
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = load_icon(ICON_PAUSED, true);
    set_tip(&mut nid, "Fingerprint Disabler");
    unsafe { Shell_NotifyIconW(NIM_ADD, &mut nid) };
    CURRENT.with_borrow_mut(|c| *c = (ICON_PAUSED, "Fingerprint Disabler".into()));
}

fn set_tip(nid: &mut NOTIFYICONDATAW, tip: &str) {
    let w: Vec<u16> = tip.encode_utf16().take(nid.szTip.len() - 1).collect();
    nid.szTip = [0; 128];
    nid.szTip[..w.len()].copy_from_slice(&w);
}

// ---------------------------------------------------------------- status --

struct View {
    svc: SvcState,
    status: Option<Status>,
    cfg: Config,
}

fn current_view() -> View {
    let svc = query_service();
    let status = if svc == SvcState::Running { load_status() } else { None };
    View { svc, status, cfg: load_config() }
}

fn lid_text(v: &View) -> String {
    match v.status.as_ref().map(|s| s.lid.as_str()) {
        Some("closed") => "Lid: closed".into(),
        Some("open") => "Lid: open".into(),
        _ => "Lid: unknown".into(),
    }
}

fn svc_text(svc: SvcState) -> &'static str {
    match svc {
        SvcState::Running => "Service: running",
        SvcState::Stopped => "Service: stopped",
        SvcState::NotInstalled => "Service: not installed",
        SvcState::Pending => "Service: starting/stopping",
        SvcState::Unknown => "Service: unknown",
    }
}

fn refresh() {
    let hwnd = MAIN_HWND.get();
    let v = current_view();
    let disabled = v.status.as_ref().map(|s| s.disabled.len()).unwrap_or(0);

    let (icon, tip) = if v.svc != SvcState::Running {
        (ICON_PAUSED, format!("Fingerprint Disabler\n{}", svc_text(v.svc)))
    } else if !v.cfg.enabled {
        (ICON_PAUSED, format!("Fingerprint Disabler (paused)\n{}", lid_text(&v)))
    } else if disabled > 0 {
        (ICON_ACTIVE, format!("Fingerprint Disabler\n{}\n{} device(s) disabled - use PIN", lid_text(&v), disabled))
    } else {
        (ICON_NORMAL, format!("Fingerprint Disabler\n{}\nWatching {} device(s)", lid_text(&v), v.cfg.devices.len()))
    };

    let changed = CURRENT.with_borrow(|c| c.0 != icon || c.1 != tip);
    if changed {
        let mut nid = nid_base(hwnd);
        nid.uFlags = NIF_ICON | NIF_TIP;
        nid.hIcon = load_icon(icon, true);
        set_tip(&mut nid, &tip);
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &mut nid) };
        CURRENT.with_borrow_mut(|c| *c = (icon, tip));
    }
}

// ------------------------------------------------------------ main window --

unsafe extern "system" fn main_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_TIMER => {
                if wp == UPDATE_TIMER_ID {
                    SetTimer(hwnd, UPDATE_TIMER_ID, UPDATE_PERIOD_MS, None);
                    if load_config().check_updates {
                        check_updates_async(false);
                    }
                } else {
                    refresh();
                }
                0
            }
            WM_UPDATE => {
                let msg = *Box::from_raw(lp as *mut UpdateMsg);
                on_update_msg(hwnd, msg);
                0
            }
            WM_REFRESH => {
                refresh();
                0
            }
            WM_TRAY => {
                match lp as u32 {
                    WM_LBUTTONUP => open_settings(),
                    WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                    NIN_BALLOONUSERCLICK => {
                        if UPDATE.with_borrow(|u| u.is_some()) {
                            prompt_update(hwnd);
                        }
                    }
                    _ => {}
                }
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            m if m == TASKBAR_CREATED.get() && m != 0 => {
                // Explorer restarted - re-add the icon.
                add_tray_icon(hwnd);
                refresh();
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

fn show_menu(hwnd: HWND) {
    let v = current_view();
    unsafe {
        let menu = CreatePopupMenu();
        let add = |flags: u32, id: usize, text: &str| {
            let t = wide(text);
            AppendMenuW(menu, flags, id, t.as_ptr());
        };
        let sep = || {
            AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        };

        add(MF_STRING | MF_GRAYED, 0, svc_text(v.svc));
        if v.svc == SvcState::Running {
            add(MF_STRING | MF_GRAYED, 0, &lid_text(&v));
            if let Some(st) = &v.status {
                for d in &st.disabled {
                    add(MF_STRING | MF_GRAYED, 0, &format!("Disabled: {}", d.name));
                }
                for e in st.errors.iter().take(3) {
                    add(MF_STRING | MF_GRAYED, 0, &format!("Error: {e}"));
                }
            }
        }
        sep();
        let checked = if v.cfg.enabled { MF_CHECKED } else { MF_UNCHECKED };
        let can_write = v.svc != SvcState::NotInstalled;
        add(MF_STRING | checked | if can_write { 0 } else { MF_GRAYED }, IDM_TOGGLE,
            "Active (disable devices when lid is closed)");
        add(MF_STRING | MF_DEFAULT, IDM_SETTINGS, "Settings...");
        add(MF_STRING | if log_path().exists() { 0 } else { MF_GRAYED }, IDM_LOG, "Open log");
        sep();
        match v.svc {
            SvcState::NotInstalled => add(MF_STRING, IDM_INSTALL, "Install service (admin)..."),
            SvcState::Stopped => {
                add(MF_STRING, IDM_START, "Start service (admin)...");
                add(MF_STRING, IDM_INSTALL, "Reinstall service (admin)...");
                add(MF_STRING, IDM_UNINSTALL, "Uninstall (admin)...");
            }
            _ => {
                add(MF_STRING, IDM_INSTALL, "Reinstall service (admin)...");
                add(MF_STRING, IDM_UNINSTALL, "Uninstall (admin)...");
            }
        }
        sep();
        let busy = if UPDATE_BUSY.get() { MF_GRAYED } else { 0 };
        match UPDATE.with_borrow(|u| u.as_ref().map(|i| i.version.clone())) {
            Some(v) => add(MF_STRING | busy, IDM_UPDATE, &format!("Update to version {v} (admin)...")),
            None => add(MF_STRING | busy, IDM_CHECK_UPDATE, &format!("Check for updates (current {VERSION})")),
        }
        add(MF_STRING, IDM_RELEASES, "Project page on GitHub");
        sep();
        add(MF_STRING, IDM_EXIT, "Exit tray icon");

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
            pt.x, pt.y, 0, hwnd, ptr::null(),
        ) as usize;
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);

        match cmd {
            IDM_SETTINGS => open_settings(),
            IDM_TOGGLE => {
                let mut cfg = load_config();
                cfg.enabled = !cfg.enabled;
                if let Err(e) = save_config(&cfg) {
                    message_box(&format!("Cannot save settings: {e}"), true);
                }
                refresh();
            }
            IDM_LOG => {
                let p = wide(&log_path().display().to_string());
                let verb = wide("open");
                ShellExecuteW(ptr::null_mut(), verb.as_ptr(), p.as_ptr(), ptr::null(), ptr::null(), SW_SHOWNORMAL);
            }
            IDM_INSTALL => run_elevated("install --gui"),
            IDM_UNINSTALL => {
                let t = wide("Uninstall the Fingerprint Disabler service?\n\nDevices it disabled will be re-enabled.");
                let c = wide("Fingerprint Disabler");
                if MessageBoxW(hwnd, t.as_ptr(), c.as_ptr(), MB_YESNO | MB_ICONQUESTION) == IDYES {
                    run_elevated("uninstall --gui");
                }
            }
            IDM_START => run_elevated("start --gui"),
            IDM_CHECK_UPDATE => check_updates_async(true),
            IDM_UPDATE => prompt_update(hwnd),
            IDM_RELEASES => open_url(&format!("https://github.com/{}", updater::REPO)),
            IDM_EXIT => {
                DestroyWindow(hwnd);
            }
            _ => {}
        }
    }
}

/// Runs `exe` elevated (UAC prompt) and waits. Returns the exit code, or
/// `None` if it could not be started (e.g. the UAC prompt was cancelled).
fn run_elevated_wait(exe: &str, args: &str) -> Option<u32> {
    unsafe {
        let exe = wide(exe);
        let verb = wide("runas");
        let params = wide(args);
        let mut sei: SHELLEXECUTEINFOW = mem::zeroed();
        sei.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = exe.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = SW_HIDE;
        if ShellExecuteExW(&mut sei) == 0 || sei.hProcess.is_null() {
            return None;
        }
        WaitForSingleObject(sei.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(sei.hProcess, &mut code);
        CloseHandle(sei.hProcess);
        Some(code)
    }
}

/// Launches this exe elevated with the given arguments and refreshes the
/// tray once it finishes.
fn run_elevated(args: &str) {
    let hwnd = MAIN_HWND.get() as isize;
    let args = args.to_string();
    std::thread::spawn(move || {
        let exe = std::env::current_exe().unwrap().display().to_string();
        run_elevated_wait(&exe, &args);
        unsafe { PostMessageW(hwnd as HWND, WM_REFRESH, 0, 0) };
    });
}

// ---------------------------------------------------------------- update --

fn balloon(title: &str, text: &str) {
    let mut nid = nid_base(MAIN_HWND.get());
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    let t: Vec<u16> = title.encode_utf16().take(nid.szInfoTitle.len() - 1).collect();
    nid.szInfoTitle[..t.len()].copy_from_slice(&t);
    let b: Vec<u16> = text.encode_utf16().take(nid.szInfo.len() - 1).collect();
    nid.szInfo[..b.len()].copy_from_slice(&b);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &mut nid) };
}

fn open_url(url: &str) {
    let u = wide(url);
    let verb = wide("open");
    unsafe { ShellExecuteW(ptr::null_mut(), verb.as_ptr(), u.as_ptr(), ptr::null(), ptr::null(), SW_SHOWNORMAL) };
}

fn check_updates_async(manual: bool) {
    if UPDATE_BUSY.replace(true) {
        return;
    }
    let hwnd = MAIN_HWND.get() as isize;
    std::thread::spawn(move || {
        let msg = match updater::check() {
            Ok(Some(info)) => UpdateMsg::Found { info, manual },
            Ok(None) => UpdateMsg::UpToDate { manual },
            Err(err) => UpdateMsg::CheckFailed { err, manual },
        };
        post_update(msg, hwnd);
    });
}

fn prompt_update(hwnd: HWND) {
    let Some(info) = UPDATE.with_borrow(|u| u.clone()) else { return };
    if UPDATE_BUSY.get() {
        return;
    }
    let text = wide(&format!(
        "Version {} is available (you have {VERSION}).\n\n\
         Download and install it now? Windows will ask for administrator rights.\n\n\
         Release notes: {}",
        info.version, info.html_url
    ));
    let cap = wide("Fingerprint Disabler update");
    let answer = unsafe { MessageBoxW(hwnd, text.as_ptr(), cap.as_ptr(), MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) };
    if answer != IDYES {
        return;
    }
    UPDATE_BUSY.set(true);
    let hwnd = hwnd as isize;
    std::thread::spawn(move || {
        // The installed copy (admin-only directory) downloads, verifies and
        // installs the update itself; nothing this process writes is run
        // elevated.
        let msg = match verified_installed_exe() {
            Err(_) if !install_dir().join(EXE_NAME).exists() => UpdateMsg::InstallFailed(Some(format!(
                "The service is not installed, so there is nothing to update.\n\nDownload version {} from {}",
                info.version, info.html_url
            ))),
            Err(e) => UpdateMsg::InstallFailed(Some(format!(
                "Refusing to run the installed program as administrator:\n{e}\n\nReinstall Fingerprint Disabler."
            ))),
            Ok(installed) => {
                let args = format!("update --gui --version \"{}\"", info.version);
                match run_elevated_wait(&installed.display().to_string(), &args) {
                    Some(0) => UpdateMsg::Installed,
                    // Failure details were already shown by the elevated updater;
                    // None = UAC prompt cancelled.
                    _ => UpdateMsg::InstallFailed(None),
                }
            }
        };
        post_update(msg, hwnd);
    });
}

fn on_update_msg(hwnd: HWND, msg: UpdateMsg) {
    UPDATE_BUSY.set(false);
    match msg {
        UpdateMsg::Found { info, manual } => {
            let v = info.version.clone();
            let already = UPDATE.with_borrow(|u| u.as_ref().is_some_and(|i| i.version == v));
            UPDATE.with_borrow_mut(|u| *u = Some(info));
            if manual {
                prompt_update(hwnd);
            } else if !already {
                balloon("Update available", &format!("Fingerprint Disabler {v} is available. Click to install."));
            }
        }
        UpdateMsg::UpToDate { manual } => {
            UPDATE.with_borrow_mut(|u| *u = None);
            if manual {
                message_box(&format!("You are running the latest version ({VERSION})."), false);
            }
        }
        UpdateMsg::CheckFailed { err, manual } => {
            if manual {
                message_box(&format!("Update check failed:\n{err}"), true);
            }
        }
        UpdateMsg::InstallFailed(err) => {
            if let Some(e) = err {
                message_box(&e, true);
            }
        }
        UpdateMsg::Installed => unsafe {
            // Hand over to the freshly installed tray and exit.
            let mut nid = nid_base(hwnd);
            Shell_NotifyIconW(NIM_DELETE, &mut nid);
            CloseHandle(MUTEX.replace(ptr::null_mut()));
            let exe = install_dir().join(EXE_NAME);
            if let Err(e) = std::process::Command::new(&exe).arg("--updated").spawn() {
                message_box(&format!("Updated, but cannot restart {}: {e}", exe.display()), true);
            }
            DestroyWindow(hwnd);
        },
    }
}

// -------------------------------------------------------- settings window --

fn scale(v: i32) -> i32 {
    let dpi = unsafe { windows_sys::Win32::UI::HiDpi::GetDpiForSystem() } as i32;
    v * dpi / 96
}

fn open_settings() {
    let existing = SETTINGS_HWND.get();
    unsafe {
        if !existing.is_null() {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
        let cls = wide("FingerprintDisablerSettings");
        let title = wide(&format!("Fingerprint Disabler {VERSION} - Settings"));
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let mut rc = RECT { left: 0, top: 0, right: scale(600), bottom: scale(430) };
        AdjustWindowRectEx(&mut rc, style, 0, WS_EX_CONTROLPARENT);
        let (w, h) = (rc.right - rc.left, rc.bottom - rc.top);
        let x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
        let hwnd = CreateWindowExW(
            WS_EX_CONTROLPARENT, cls.as_ptr(), title.as_ptr(), style, x, y, w, h,
            ptr::null_mut(), ptr::null_mut(), hinstance(), ptr::null(),
        );
        SETTINGS_HWND.set(hwnd);
        build_settings(hwnd);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

fn ctl(parent: HWND, class: &str, text: &str, style: u32, ex: u32, x: i32, y: i32, w: i32, h: i32, id: i32) -> HWND {
    let c = wide(class);
    let t = wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            ex, c.as_ptr(), t.as_ptr(), WS_CHILD | WS_VISIBLE | style,
            scale(x), scale(y), scale(w), scale(h),
            parent, id as isize as HMENU, hinstance(), ptr::null(),
        );
        SendMessageW(hwnd, WM_SETFONT, FONT.get() as WPARAM, 1);
        hwnd
    }
}

fn build_settings(hwnd: HWND) {
    let cfg = load_config();
    let svc = query_service();

    ctl(hwnd, "STATIC", "Biometric devices to disable while the lid is closed (checked = disable):",
        0, 0, 12, 12, 576, 18, -1);

    let list = ctl(hwnd, "SysListView32", "",
        WS_TABSTOP | (LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER) as u32,
        WS_EX_CLIENTEDGE, 12, 34, 576, 200, IDC_LIST);
    unsafe {
        let ex = LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER;
        SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, ex as WPARAM, ex as LPARAM);
        for (i, (name, width)) in [("Device", 250), ("State", 110), ("Instance ID", 400)].iter().enumerate() {
            let t = wide(name);
            let mut col: LVCOLUMNW = mem::zeroed();
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.cx = scale(*width);
            col.pszText = t.as_ptr() as *mut u16;
            SendMessageW(list, LVM_INSERTCOLUMNW, i, &col as *const _ as LPARAM);
        }
    }
    fill_list(list, &cfg.devices);

    let active = ctl(hwnd, "BUTTON", "&Active - disable the checked devices when the lid is closed",
        WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, 12, 244, 576, 20, IDC_ACTIVE);
    unsafe { SendMessageW(active, BM_SETCHECK, if cfg.enabled { BST_CHECKED } else { BST_UNCHECKED } as WPARAM, 0) };

    ctl(hwnd, "STATIC", "&Polling interval (ms):", 0, 0, 12, 277, 150, 18, -1);
    ctl(hwnd, "EDIT", &cfg.poll_interval_ms.to_string(),
        WS_TABSTOP | (ES_NUMBER | ES_AUTOHSCROLL) as u32, WS_EX_CLIENTEDGE, 165, 274, 80, 22, IDC_INTERVAL);
    ctl(hwnd, "STATIC", &format!("({MIN_POLL_MS} - {MAX_POLL_MS}; lid changes are applied instantly)"),
        0, 0, 255, 277, 330, 18, -1);

    let upd = ctl(hwnd, "BUTTON", "Check for &updates automatically (GitHub releases)",
        WS_TABSTOP | BS_AUTOCHECKBOX as u32, 0, 12, 304, 576, 20, IDC_UPDATES);
    unsafe { SendMessageW(upd, BM_SETCHECK, if cfg.check_updates { BST_CHECKED } else { BST_UNCHECKED } as WPARAM, 0) };

    let svc_line = match svc {
        SvcState::Running => "Service is running. Changes are applied within one polling interval.".to_string(),
        SvcState::NotInstalled => "The background service is NOT installed. Use the tray menu -> \"Install service\" (needs admin).".to_string(),
        other => format!("{} - devices are not being managed.", svc_text(other)),
    };
    ctl(hwnd, "STATIC", &svc_line, 0, 0, 12, 336, 576, 40, -1);

    ctl(hwnd, "BUTTON", "&Refresh", WS_TABSTOP, 0, 12, 390, 90, 28, IDC_REFRESH);
    ctl(hwnd, "BUTTON", "Save", WS_TABSTOP | BS_DEFPUSHBUTTON as u32, 0, 400, 390, 90, 28, IDOK);
    ctl(hwnd, "BUTTON", "Cancel", WS_TABSTOP, 0, 498, 390, 90, 28, IDCANCEL);
    unsafe { SetFocus(list) };
}

fn lv_set_text(list: HWND, row: i32, col: i32, text: &str) {
    let t = wide(text);
    unsafe {
        let mut item: LVITEMW = mem::zeroed();
        item.iSubItem = col;
        item.pszText = t.as_ptr() as *mut u16;
        SendMessageW(list, LVM_SETITEMTEXTW, row as WPARAM, &item as *const _ as LPARAM);
    }
}

fn fill_list(list: HWND, checked_ids: &[String]) {
    let owned: Vec<String> = load_status()
        .map(|s| s.disabled.into_iter().map(|d| d.id.to_uppercase()).collect())
        .unwrap_or_default();
    let mut rows: Vec<(String, String, String)> = Vec::new(); // id, name, state
    match devices::enumerate() {
        Ok(devs) => {
            for d in devs {
                let state = if d.disabled {
                    if owned.contains(&d.instance_id.to_uppercase()) { "Disabled (by app)" } else { "Disabled" }
                } else if d.problem != 0 {
                    "Problem"
                } else {
                    "Enabled"
                };
                rows.push((d.instance_id, d.name, state.into()));
            }
        }
        Err(e) => message_box(&format!("Cannot enumerate devices: {e}"), true),
    }
    // Configured devices that are currently not present (e.g. USB reader unplugged).
    for id in checked_ids {
        if !rows.iter().any(|r| r.0.eq_ignore_ascii_case(id)) {
            rows.push((id.clone(), "(device not present)".into(), "Not present".into()));
        }
    }

    unsafe {
        SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
        for (i, (id, name, state)) in rows.iter().enumerate() {
            let t = wide(name);
            let mut item: LVITEMW = mem::zeroed();
            item.mask = LVIF_TEXT;
            item.iItem = i as i32;
            item.pszText = t.as_ptr() as *mut u16;
            let row = SendMessageW(list, LVM_INSERTITEMW, 0, &item as *const _ as LPARAM) as i32;
            lv_set_text(list, row, 1, state);
            lv_set_text(list, row, 2, id);
            if checked_ids.iter().any(|c| c.eq_ignore_ascii_case(id)) {
                let mut st: LVITEMW = mem::zeroed();
                st.stateMask = LVIS_STATEIMAGEMASK;
                st.state = 2 << 12; // INDEXTOSTATEIMAGEMASK(2) = checked
                SendMessageW(list, LVM_SETITEMSTATE, row as WPARAM, &st as *const _ as LPARAM);
            }
        }
    }
    LIST_IDS.with_borrow_mut(|v| *v = rows.into_iter().map(|r| r.0).collect());
}

fn checked_ids(list: HWND) -> Vec<String> {
    LIST_IDS.with_borrow(|ids| {
        ids.iter()
            .enumerate()
            .filter(|(i, _)| unsafe {
                let st = SendMessageW(list, LVM_GETITEMSTATE, *i, LVIS_STATEIMAGEMASK as LPARAM) as u32;
                (st >> 12) == 2
            })
            .map(|(_, id)| id.clone())
            .collect()
    })
}

fn save_settings(hwnd: HWND) -> bool {
    unsafe {
        let list = GetDlgItem(hwnd, IDC_LIST);
        let mut buf = [0u16; 32];
        GetWindowTextW(GetDlgItem(hwnd, IDC_INTERVAL), buf.as_mut_ptr(), buf.len() as i32);
        let interval: u64 = match from_wide(&buf).trim().parse() {
            Ok(v) if (MIN_POLL_MS..=MAX_POLL_MS).contains(&v) => v,
            _ => {
                message_box(&format!("Polling interval must be between {MIN_POLL_MS} and {MAX_POLL_MS} ms."), true);
                SetFocus(GetDlgItem(hwnd, IDC_INTERVAL));
                return false;
            }
        };
        let cfg = Config {
            enabled: SendMessageW(GetDlgItem(hwnd, IDC_ACTIVE), BM_GETCHECK, 0, 0) == BST_CHECKED as isize,
            poll_interval_ms: interval,
            devices: checked_ids(list),
            check_updates: SendMessageW(GetDlgItem(hwnd, IDC_UPDATES), BM_GETCHECK, 0, 0) == BST_CHECKED as isize,
        };
        if let Err(e) = save_config(&cfg) {
            message_box(
                &format!(
                    "Cannot save settings to {}:\n{e}\n\nInstall the service first (tray menu -> Install service).",
                    config_path().display()
                ),
                true,
            );
            return false;
        }
    }
    true
}

unsafe extern "system" fn settings_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_COMMAND => {
                let id = (wp & 0xFFFF) as i32;
                match id {
                    IDOK => {
                        if save_settings(hwnd) {
                            DestroyWindow(hwnd);
                            PostMessageW(MAIN_HWND.get(), WM_REFRESH, 0, 0);
                        }
                    }
                    IDCANCEL => {
                        DestroyWindow(hwnd);
                    }
                    IDC_REFRESH => {
                        let list = GetDlgItem(hwnd, IDC_LIST);
                        let ids = checked_ids(list);
                        fill_list(list, &ids);
                    }
                    _ => {}
                }
                0
            }
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                SETTINGS_HWND.set(ptr::null_mut());
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

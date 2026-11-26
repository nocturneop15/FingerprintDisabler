//! Fingerprint Disabler
//!
//! Disables selected biometric devices (fingerprint readers, ...) while the
//! laptop lid is closed - typically when docked with external monitors - so
//! Windows Hello offers the PIN instead of waiting for an unreachable sensor.
//! The devices are re-enabled as soon as the lid opens.
//!
//!   fingerprint-disabler.exe              tray icon + settings (normal user)
//!   fingerprint-disabler.exe install      install/update service + autostart (admin)
//!   fingerprint-disabler.exe uninstall    remove everything, re-enable devices (admin)
//!   fingerprint-disabler.exe start        start the service (admin)
//!   fingerprint-disabler.exe update       download, verify and install the latest release (admin)
//!   fingerprint-disabler.exe list         list biometric devices
//!   fingerprint-disabler.exe check-update check GitHub releases for a newer version
//!   fingerprint-disabler.exe --console    run the worker in a console window (admin, testing)
//!   fingerprint-disabler.exe --service    entry point used by the Service Control Manager

#![windows_subsystem = "windows"]

mod common;
mod devices;
mod install;
mod service;
mod tray;
mod trust;
mod updater;

use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AllocConsole, AttachConsole};

const USAGE: &str = "\
Fingerprint Disabler - disables selected biometric devices while the laptop lid is closed.

Usage: fingerprint-disabler.exe [command]

  (no command)   tray icon + settings window
  install        install/update the service and tray autostart (admin)
  uninstall      remove the service, re-enable devices (admin; --force: even if
                 some devices could not be re-enabled)
  update         download, verify and install the latest release (admin)
  start          start the service (admin)
  list           list biometric devices
  check-update   check GitHub for a newer release (--download: also fetch + verify)
  --console      run the worker in the foreground for testing (admin)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let gui = args.iter().any(|a| a == "--gui");
    match args.first().map(String::as_str) {
        None => tray::run(false),
        Some("--updated") => tray::run(true),
        Some("--service") => service::run_service(),
        Some("--console") => {
            unsafe { AllocConsole() };
            service::run_console();
        }
        Some(cmd @ ("install" | "uninstall" | "start" | "update")) => {
            if !gui {
                unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
            }
            std::process::exit(install::run(cmd, &args));
        }
        Some("check-update") => {
            unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
            println!();
            match updater::check() {
                Ok(Some(u)) => {
                    println!("Update available: {} ({})", u.version, u.asset_url);
                    if args.iter().any(|a| a == "--download") {
                        match updater::download(&u) {
                            Ok(p) => println!("Downloaded and SHA-256 verified: {}", p.display()),
                            Err(e) => {
                                eprintln!("Download failed: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
                Ok(None) => println!("Up to date ({}).", updater::VERSION),
                Err(e) => {
                    eprintln!("Update check failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("list") => {
            unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
            println!();
            match devices::enumerate() {
                Ok(list) if list.is_empty() => println!("No biometric devices found."),
                Ok(list) => {
                    for d in list {
                        let state = if !d.status_known { "UNKNOWN" } else if d.disabled { "DISABLED" } else if d.problem != 0 { "PROBLEM" } else { "enabled" };
                        println!("{:<9} {}\n          {}", state, d.name, d.instance_id);
                    }
                }
                Err(e) => eprintln!("enumeration failed: {e}"),
            }
        }
        Some(_) => {
            unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
            println!("\n{USAGE}");
        }
    }
}

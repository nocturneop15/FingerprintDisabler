# Fingerprint Disabler

When a Windows laptop sits closed in a dock, Windows Hello keeps asking for a
fingerprint on a reader you can't reach. This tool disables the biometric
devices you choose while the lid is closed, so Windows Hello falls back to the
PIN. It re-enables them as soon as the lid opens.

## Architecture

One executable, two roles:

| Role | Runs as | Purpose |
|---|---|---|
| `fingerprint-disabler.exe --service` | Windows service, LocalSystem, auto start | Receives lid open/close events and enables or disables the devices (needs admin rights). It starts before logon, so the lock screen after boot is also covered. |
| `fingerprint-disabler.exe` | Tray icon, normal user, starts at logon | Shows status, settings window, install/uninstall. |

* **Lid detection:** the service registers for `GUID_LIDSWITCH_STATE_CHANGE`.
  Windows sends the current state on registration and on every change, so the
  reaction is immediate.
* **Polling interval** (default 500 ms): on each tick the service reloads
  settings and re-checks the devices. If something turns a device back on
  while the lid is closed (a driver update, PnP, Device Manager), it gets
  disabled again.
* **Device control:** SetupAPI `DIF_PROPERTYCHANGE` (`DICS_ENABLE` /
  `DICS_DISABLE`), the same mechanism Device Manager uses. Only devices in the
  *Biometric* class are listed.
* **Safety:**
  * The service re-enables only devices that it disabled itself. These are
    tracked in `state.json`, so this also works after a crash.
  * It never touches a device that you disabled manually.
  * Stopping or uninstalling the service re-enables everything it disabled.
  * On system shutdown the current state is kept. If the laptop boots docked,
    the reader is already off at the lock screen. If it boots with the lid
    open, the first lid notification turns the reader back on.
* **Files:** `C:\ProgramData\FingerprintDisabler\`
  * `config.json` is writable by Users, so the non-elevated tray can save it.
  * `status.json`, `state.json` and `service.log` are written by the service.

## Download

Get `fingerprint-disabler.exe` from the
[latest release](https://github.com/nocturneop15/FingerprintDisabler/releases/latest).

## Install

Run `fingerprint-disabler.exe`. It opens Settings on first run.
Then right-click the tray icon and choose **Install service (admin)…**.

You can also run this from an elevated prompt:

```
fingerprint-disabler.exe install
```

`install` does the following:

1. Copies the exe to `C:\Program Files\FingerprintDisabler\`.
2. Registers and starts the service. It is set to start automatically and to
   restart on failure.
3. Adds the tray to `HKLM\...\Run`.

Next, open **Settings** from the tray (left-click the icon), check the
fingerprint reader, and click **Save**.

Other commands: `uninstall`, `start`, `list`, `check-update`, `--console`
(runs the worker in the foreground for testing; needs an elevated prompt).

## Updates

The tray checks
[GitHub releases](https://github.com/nocturneop15/FingerprintDisabler/releases)
15 seconds after start and then once a day. You can turn this off in Settings.
You can also check manually from the tray menu with **Check for updates**.

When a newer version exists, a notification appears. Clicking it, or choosing
**Update to version X** in the menu, does the following:

1. Downloads `fingerprint-disabler.exe` from the release.
2. Verifies its SHA-256 against the digest GitHub publishes for that release
   asset.
3. Runs `install` elevated (UAC prompt). This replaces the program in
   Program Files and restarts the service.
4. Relaunches the tray.

## Build

```
cargo build --release
```

The icons are generated in `build.rs` and embedded together with a
common-controls v6 manifest (via windres on the GNU toolchain, rc.exe on MSVC).

### Releasing

1. Bump `version` in `Cargo.toml`.
2. Commit, then tag `vX.Y.Z` and push the tag.

The [release workflow](.github/workflows/release.yml) builds the exe on GitHub
Actions and publishes the release with the exe and a `.sha256` file.

## Tray icon

* Blue: watching, devices enabled.
* Red with a slash: lid closed, devices disabled, use your PIN.
* Gray: paused, or the service is not running.

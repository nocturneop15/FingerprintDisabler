//! Enumeration and enable/disable of devices in the "Biometric" device class
//! via SetupAPI (same mechanism Device Manager / devcon use).

use crate::common::from_wide;
use std::{io, mem, ptr};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
use windows_sys::core::GUID;

/// Problem code of a device whose change Windows finishes after a restart.
pub use windows_sys::Win32::Devices::DeviceAndDriverInstallation::CM_PROB_NEED_RESTART;

/// {53D29EF7-377C-4D14-864B-EB3A85769359} - Biometric devices class.
pub const GUID_DEVCLASS_BIOMETRIC: GUID = GUID::from_u128(0x53d29ef7_377c_4d14_864b_eb3a85769359);

#[derive(Clone, Debug)]
pub struct BioDevice {
    pub instance_id: String,
    pub name: String,
    pub disabled: bool,
    /// Device has some other problem (driver error etc.).
    pub problem: u32,
    /// False if Windows could not report the device's status. `disabled`
    /// and `problem` are then meaningless: treat the state as unknown.
    pub status_known: bool,
}

struct DevInfoSet(HDEVINFO);

impl Drop for DevInfoSet {
    fn drop(&mut self) {
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

impl DevInfoSet {
    fn open() -> io::Result<Self> {
        let h = unsafe {
            SetupDiGetClassDevsW(&GUID_DEVCLASS_BIOMETRIC, ptr::null(), ptr::null_mut(), DIGCF_PRESENT)
        };
        if h as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }

    fn iter(&self) -> impl Iterator<Item = SP_DEVINFO_DATA> + '_ {
        let mut index = 0u32;
        std::iter::from_fn(move || unsafe {
            let mut data: SP_DEVINFO_DATA = mem::zeroed();
            data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as u32;
            if SetupDiEnumDeviceInfo(self.0, index, &mut data) == 0 {
                return None;
            }
            index += 1;
            Some(data)
        })
    }

    fn instance_id(&self, data: &SP_DEVINFO_DATA) -> String {
        let mut buf = [0u16; 512];
        let mut req = 0u32;
        unsafe {
            SetupDiGetDeviceInstanceIdW(self.0, data, buf.as_mut_ptr(), buf.len() as u32, &mut req);
        }
        from_wide(&buf)
    }

    fn property(&self, data: &SP_DEVINFO_DATA, prop: u32) -> Option<String> {
        let mut buf = [0u16; 512];
        let mut req = 0u32;
        let mut ty = 0u32;
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.0,
                data,
                prop,
                &mut ty,
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 2) as u32,
                &mut req,
            )
        };
        let s = from_wide(&buf);
        (ok != 0 && !s.is_empty()).then_some(s)
    }

    fn describe(&self, data: &SP_DEVINFO_DATA) -> BioDevice {
        let instance_id = self.instance_id(data);
        let name = self
            .property(data, SPDRP_FRIENDLYNAME)
            .or_else(|| self.property(data, SPDRP_DEVICEDESC))
            .unwrap_or_else(|| instance_id.clone());
        let (mut status, mut problem) = (0u32, 0u32);
        let cr = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, data.DevInst, 0) };
        let status_known = cr == CR_SUCCESS;
        let has_problem = status_known && (status & DN_HAS_PROBLEM) != 0;
        let disabled = has_problem && problem == CM_PROB_DISABLED;
        BioDevice { instance_id, name, disabled, problem: if has_problem { problem } else { 0 }, status_known }
    }
}

/// Lists all present biometric devices (including disabled ones).
pub fn enumerate() -> io::Result<Vec<BioDevice>> {
    let set = DevInfoSet::open()?;
    let mut list: Vec<BioDevice> = set.iter().map(|d| set.describe(&d)).collect();
    list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(list)
}

/// Enables or disables a device. Requires administrator / SYSTEM rights.
/// Returns `Ok(true)` when Windows reports that a reboot is needed.
pub fn set_enabled(instance_id: &str, enable: bool) -> io::Result<bool> {
    let set = DevInfoSet::open()?;
    let data = set
        .iter()
        .find(|d| set.instance_id(d).eq_ignore_ascii_case(instance_id))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "device not present"))?;

    unsafe {
        let mut params: SP_PROPCHANGE_PARAMS = mem::zeroed();
        params.ClassInstallHeader.cbSize = mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32;
        params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        params.StateChange = if enable { DICS_ENABLE } else { DICS_DISABLE };
        params.Scope = DICS_FLAG_GLOBAL;
        params.HwProfile = 0;

        if SetupDiSetClassInstallParamsW(
            set.0,
            &data,
            &params.ClassInstallHeader,
            mem::size_of::<SP_PROPCHANGE_PARAMS>() as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set.0, &data) == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ip: SP_DEVINSTALL_PARAMS_W = mem::zeroed();
        ip.cbSize = mem::size_of::<SP_DEVINSTALL_PARAMS_W>() as u32;
        let reboot = SetupDiGetDeviceInstallParamsW(set.0, &data, &mut ip) != 0
            && (ip.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
        Ok(reboot)
    }
}

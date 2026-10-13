use ledger_device_sdk::nvm::*;
use ledger_device_sdk::NVMData;

/// Index of the switch allowing transactions that carry source code
/// (`m_addpkg`, `m_run`), which cannot be reviewed on the device. NVM starts
/// zeroed, so it is off until the user turns it on.
pub const SETTING_PACKAGE_TX: usize = 0;

pub const SETTINGS_STRINGS: [[&str; 2]; 1] = [["Packages", "Allow deploying and running code"]];

// This is necessary to store the object in NVM and not in RAM
const SETTINGS_SIZE: usize = 10;
#[link_section = ".nvm_data"]
static mut DATA: NVMData<AtomicStorage<[u8; SETTINGS_SIZE]>> =
    NVMData::new(AtomicStorage::new(&[0u8; SETTINGS_SIZE]));

#[derive(Clone, Copy)]
pub struct Settings;

impl Default for Settings {
    fn default() -> Self {
        Settings
    }
}

impl Settings {
    #[inline(never)]
    #[allow(unused)]
    pub fn get_mut(&mut self) -> &mut AtomicStorage<[u8; SETTINGS_SIZE]> {
        let data = &raw mut DATA;
        unsafe { (*data).get_mut() }
    }

    #[inline(never)]
    #[allow(unused)]
    pub fn get_ref(&mut self) -> &AtomicStorage<[u8; SETTINGS_SIZE]> {
        let data = &raw const DATA;
        unsafe { (*data).get_ref() }
    }

    #[allow(unused)]
    pub fn get_element(&self, index: usize) -> u8 {
        let data = &raw const DATA;
        let storage = unsafe { (*data).get_ref() };
        let settings = storage.get_ref();
        settings[index]
    }

    #[allow(unused)]
    pub fn set_element(&self, index: usize, value: u8) {
        let data = &raw mut DATA;
        let storage = unsafe { (*data).get_mut() };
        let mut updated_data = *storage.get_ref();
        updated_data[index] = value;
        unsafe {
            storage.update(&updated_data);
        }
    }
}

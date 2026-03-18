use winreg::enums::*;
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "irohWebProxy";

pub fn is_enabled() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey(RUN_KEY) {
        Ok(key) => key.get_value::<String, _>(VALUE_NAME).is_ok(),
        Err(_) => false,
    }
}

pub fn set_enabled(enabled: bool) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if enabled {
        if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_WRITE) {
            if let Ok(exe_path) = std::env::current_exe() {
                let _ = key.set_value(VALUE_NAME, &exe_path.to_string_lossy().to_string());
            }
        }
    } else {
        if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_WRITE) {
            let _ = key.delete_value(VALUE_NAME);
        }
    }
}

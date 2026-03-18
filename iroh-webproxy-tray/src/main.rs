#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod login_item;
#[cfg(windows)]
mod preferences;
#[cfg(windows)]
mod proxy_manager;
#[cfg(windows)]
mod settings;

fn main() {
    #[cfg(not(windows))]
    {
        eprintln!("iroh-webproxy-tray is only supported on Windows");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        if let Err(e) = app::run() {
            let wide_msg: Vec<u16> = format!("Fatal error: {}", e)
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let wide_title: Vec<u16> = "iroh Web Proxy"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                    std::ptr::null_mut(),
                    wide_msg.as_ptr(),
                    wide_title.as_ptr(),
                    0x10, // MB_ICONERROR
                );
            }
        }
    }
}

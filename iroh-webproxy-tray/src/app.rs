use muda::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::login_item;
use crate::preferences;
use crate::proxy_manager::ProxyManager;
use crate::settings::Settings;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize NWG (needed for preferences dialog later)
    native_windows_gui::init()?;

    // Load settings and detect existing proxy processes
    let mut settings = Settings::load();
    let mut proxy_manager = ProxyManager::new();
    proxy_manager.detect_existing(&settings);

    // Auto-restart if proxy was running before
    if settings.proxy_was_running && !proxy_manager.is_running() {
        if let Ok(()) = proxy_manager.start(&settings) {
            if let Some(ref id) = proxy_manager.server_node_id {
                settings.saved_server_node_id = id.clone();
                settings.save();
            }
        }
    }

    // Create menu items
    let status_item = MenuItem::with_id(
        MenuId::new("status"),
        status_text(&proxy_manager, &settings),
        false,
        None,
    );
    let node_id_item = MenuItem::with_id(
        MenuId::new("node_id"),
        node_id_text(&proxy_manager),
        proxy_manager.server_node_id.is_some(),
        None,
    );
    let start_stop_item = MenuItem::with_id(
        MenuId::new("start_stop"),
        start_stop_text(&proxy_manager),
        true,
        None,
    );
    let prefs_item = MenuItem::with_id(
        MenuId::new("preferences"),
        "Preferences...",
        true,
        None,
    );
    let login_check = CheckMenuItem::with_id(
        MenuId::new("login"),
        "Start at Login",
        true,
        login_item::is_enabled(),
        None,
    );
    let quit_item = MenuItem::with_id(MenuId::new("quit"), "Quit", true, None);

    // Build context menu
    let menu = Menu::new();
    menu.append(&status_item)?;
    menu.append(&node_id_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&start_stop_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&prefs_item)?;
    menu.append(&login_check)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&quit_item)?;

    // Create tray icon
    let initial_icon = if proxy_manager.is_running() {
        make_icon(76, 175, 80)
    } else {
        make_icon(158, 158, 158)
    };
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(initial_icon)
        .with_tooltip("iroh Web Proxy")
        .build()?;

    // Set up periodic timer for process monitoring (5 seconds)
    unsafe {
        SetTimer(std::ptr::null_mut(), 1, 5000, None);
    }

    // Pre-create MenuId constants for comparison
    let id_quit = MenuId::new("quit");
    let id_start_stop = MenuId::new("start_stop");
    let id_node_id = MenuId::new("node_id");
    let id_prefs = MenuId::new("preferences");
    let id_login = MenuId::new("login");

    let menu_rx = MenuEvent::receiver();

    // Win32 message loop
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    loop {
        let ret = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
        if ret == 0 || ret == -1 {
            break;
        }

        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Periodic process liveness check
        if msg.message == WM_TIMER {
            if proxy_manager.check_alive() {
                update_items(
                    &proxy_manager,
                    &settings,
                    &status_item,
                    &node_id_item,
                    &start_stop_item,
                    &tray,
                );
                if !proxy_manager.is_running() {
                    settings.proxy_was_running = false;
                    settings.saved_server_node_id.clear();
                    settings.save();
                }
            }
        }

        // Handle menu events
        while let Ok(event) = menu_rx.try_recv() {
            if event.id == id_quit {
                unsafe {
                    PostQuitMessage(0);
                }
            } else if event.id == id_start_stop {
                if proxy_manager.is_running() {
                    proxy_manager.stop_all();
                    settings.proxy_was_running = false;
                    settings.saved_server_node_id.clear();
                } else {
                    match proxy_manager.start(&settings) {
                        Ok(()) => {
                            settings.proxy_was_running = true;
                            if let Some(ref id) = proxy_manager.server_node_id {
                                settings.saved_server_node_id = id.clone();
                            }
                        }
                        Err(e) => {
                            show_error(&format!("Failed to start proxy: {}", e));
                        }
                    }
                }
                settings.save();
                update_items(
                    &proxy_manager,
                    &settings,
                    &status_item,
                    &node_id_item,
                    &start_stop_item,
                    &tray,
                );
            } else if event.id == id_node_id {
                if let Some(ref id) = proxy_manager.server_node_id {
                    copy_to_clipboard(id);
                }
            } else if event.id == id_prefs {
                if let Some(new_settings) = preferences::show_preferences(&settings) {
                    let was_running = proxy_manager.is_running();
                    if was_running {
                        proxy_manager.stop_all();
                    }
                    // Preserve runtime state fields
                    settings = new_settings;
                    settings.proxy_was_running = was_running;
                    settings.save();
                    if was_running {
                        match proxy_manager.start(&settings) {
                            Ok(()) => {
                                if let Some(ref id) = proxy_manager.server_node_id {
                                    settings.saved_server_node_id = id.clone();
                                    settings.save();
                                }
                            }
                            Err(e) => {
                                settings.proxy_was_running = false;
                                settings.save();
                                show_error(&format!("Failed to restart proxy: {}", e));
                            }
                        }
                    }
                    update_items(
                        &proxy_manager,
                        &settings,
                        &status_item,
                        &node_id_item,
                        &start_stop_item,
                        &tray,
                    );
                }
            } else if event.id == id_login {
                let enabled = login_item::is_enabled();
                login_item::set_enabled(!enabled);
                login_check.set_checked(!enabled);
            }
        }
    }

    Ok(())
}

fn update_items(
    pm: &ProxyManager,
    settings: &Settings,
    status_item: &MenuItem,
    node_id_item: &MenuItem,
    start_stop_item: &MenuItem,
    tray: &TrayIcon,
) {
    status_item.set_text(status_text(pm, settings));
    node_id_item.set_text(node_id_text(pm));
    node_id_item.set_enabled(pm.server_node_id.is_some());
    start_stop_item.set_text(start_stop_text(pm));

    let icon = if pm.is_running() {
        make_icon(76, 175, 80)
    } else {
        make_icon(158, 158, 158)
    };
    let _ = tray.set_icon(Some(icon));
}

fn status_text(pm: &ProxyManager, settings: &Settings) -> String {
    if pm.is_running() {
        let mode_display = match settings.mode.as_str() {
            "client" => "Client",
            "server" => "Server",
            "both" => "Client + Server",
            _ => &settings.mode,
        };
        format!("Status: Running ({})", mode_display)
    } else {
        "Status: Stopped".into()
    }
}

fn node_id_text(pm: &ProxyManager) -> String {
    if let Some(ref id) = pm.server_node_id {
        if id.len() > 16 {
            format!("Node ID: {}...{}", &id[..8], &id[id.len() - 8..])
        } else {
            format!("Node ID: {}", id)
        }
    } else {
        "Node ID: -".into()
    }
}

fn start_stop_text(pm: &ProxyManager) -> String {
    if pm.is_running() {
        "Stop Proxy".into()
    } else {
        "Start Proxy".into()
    }
}

fn make_icon(r: u8, g: u8, b: u8) -> Icon {
    let size = 32u32;
    let mut data = vec![0u8; (size * size * 4) as usize];
    let c = size as f32 / 2.0;
    let rad = c - 2.0;
    let dr = (r as f32 * 0.45) as u8;
    let dg = (g as f32 * 0.45) as u8;
    let db = (b as f32 * 0.45) as u8;

    for y in 0..size {
        for x in 0..size {
            let px = (y * size + x) as usize * 4;
            let fx = x as f32 - c + 0.5;
            let fy = y as f32 - c + 0.5;
            let dist = (fx * fx + fy * fy).sqrt();

            if dist > rad + 1.0 {
                continue;
            }

            let alpha = if dist > rad {
                ((rad + 1.0 - dist) * 255.0) as u8
            } else {
                255u8
            };

            let border = dist > rad - 1.5 && dist <= rad;
            let equator = fy.abs() < 0.8 && dist < rad;
            let meridian = fx.abs() < 0.8 && dist < rad;
            let lat_line = ((fy - rad / 3.0).abs() < 0.7 || (fy + rad / 3.0).abs() < 0.7)
                && dist < rad;
            let ex = fx / (rad * 0.45);
            let ey = fy / rad;
            let ed = (ex * ex + ey * ey).sqrt();
            let longitude = (ed - 1.0).abs() < 0.12 && dist < rad;

            if border || equator || meridian || lat_line || longitude {
                data[px] = dr;
                data[px + 1] = dg;
                data[px + 2] = db;
                data[px + 3] = alpha;
            } else if dist <= rad {
                data[px] = r;
                data[px + 1] = g;
                data[px + 2] = b;
                data[px + 3] = alpha;
            }
        }
    }

    Icon::from_rgba(data, size, size).expect("valid icon data")
}

fn copy_to_clipboard(text: &str) {
    use windows_sys::Win32::System::DataExchange::*;
    use windows_sys::Win32::System::Memory::*;

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * 2;

    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return;
        }
        EmptyClipboard();

        let hmem = GlobalAlloc(0x0002 /* GMEM_MOVEABLE */, byte_len);
        if hmem.is_null() {
            CloseClipboard();
            return;
        }

        let ptr = GlobalLock(hmem);
        if !ptr.is_null() {
            std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, ptr as *mut u8, byte_len);
            GlobalUnlock(hmem);
        }

        SetClipboardData(13 /* CF_UNICODETEXT */, hmem as _);
        CloseClipboard();
    }
}

fn show_error(msg: &str) {
    let wide_msg: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_title: Vec<u16> = "iroh Web Proxy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide_msg.as_ptr(),
            wide_title.as_ptr(),
            0x10, // MB_ICONERROR
        );
    }
}

extern crate native_windows_derive as nwd;
extern crate native_windows_gui as nwg;

use nwd::NwgUi;
use nwg::NativeUi;
use std::cell::{Cell, RefCell};

use crate::settings::Settings;

#[derive(Default, NwgUi)]
pub struct PreferencesDialog {
    #[nwg_control(size: (430, 560), position: (300, 200), title: "iroh Web Proxy Preferences",
                  flags: "WINDOW|VISIBLE")]
    #[nwg_events(OnWindowClose: [PreferencesDialog::on_close])]
    window: nwg::Window,

    // --- Mode ---
    #[nwg_control(text: "Mode:", size: (100, 25), position: (15, 17))]
    mode_label: nwg::Label,

    #[nwg_control(size: (200, 100), position: (120, 12),
                  collection: vec!["Client".to_string(), "Server".to_string(), "Both".to_string()])]
    #[nwg_events(OnComboxBoxSelection: [PreferencesDialog::on_mode_change])]
    mode_combo: nwg::ComboBox<String>,

    // --- Client Settings ---
    #[nwg_control(text: "--- Client Settings ---", size: (390, 20), position: (15, 50))]
    client_section: nwg::Label,

    #[nwg_control(text: "HTTP Port:", size: (100, 25), position: (15, 77))]
    http_port_label: nwg::Label,

    #[nwg_control(text: "8080", size: (200, 23), position: (120, 75))]
    http_port_input: nwg::TextInput,

    #[nwg_control(text: "HTTPS Port:", size: (100, 25), position: (15, 107))]
    https_port_label: nwg::Label,

    #[nwg_control(text: "8443", size: (200, 23), position: (120, 105))]
    https_port_input: nwg::TextInput,

    #[nwg_control(text: "Self-signed HTTPS", size: (280, 25), position: (120, 133))]
    self_sign_check: nwg::CheckBox,

    #[nwg_control(text: "Bind Address:", size: (100, 25), position: (15, 163))]
    bind_addr_label: nwg::Label,

    #[nwg_control(text: "127.0.0.1", size: (200, 23), position: (120, 161))]
    bind_addr_input: nwg::TextInput,

    #[nwg_control(text: "Host Suffix:", size: (100, 25), position: (15, 193))]
    host_suffix_label: nwg::Label,

    #[nwg_control(text: "localhost", size: (200, 23), position: (120, 191))]
    host_suffix_input: nwg::TextInput,

    // --- Server Settings ---
    #[nwg_control(text: "--- Server Settings ---", size: (390, 20), position: (15, 225))]
    server_section: nwg::Label,

    #[nwg_control(text: "Target Host:", size: (100, 25), position: (15, 252))]
    target_host_label: nwg::Label,

    #[nwg_control(text: "127.0.0.1", size: (200, 23), position: (120, 250))]
    target_host_input: nwg::TextInput,

    #[nwg_control(text: "Target Port:", size: (100, 25), position: (15, 282))]
    target_port_label: nwg::Label,

    #[nwg_control(text: "8088", size: (200, 23), position: (120, 280))]
    target_port_input: nwg::TextInput,

    #[nwg_control(text: "Connect via TLS", size: (280, 25), position: (120, 310))]
    #[nwg_events(OnButtonClick: [PreferencesDialog::on_tls_change])]
    tls_check: nwg::CheckBox,

    #[nwg_control(text: "Skip TLS verification", size: (280, 25), position: (120, 338))]
    insecure_check: nwg::CheckBox,

    #[nwg_control(text: "Key File:", size: (100, 25), position: (15, 370))]
    key_file_label: nwg::Label,

    #[nwg_control(text: "", size: (165, 23), position: (120, 368))]
    key_file_input: nwg::TextInput,

    #[nwg_control(text: "Browse...", size: (70, 23), position: (290, 368))]
    #[nwg_events(OnButtonClick: [PreferencesDialog::on_browse_key_file])]
    key_file_browse: nwg::Button,

    // --- Advanced ---
    #[nwg_control(text: "--- Advanced ---", size: (390, 20), position: (15, 405))]
    advanced_section: nwg::Label,

    #[nwg_control(text: "Binary Path:", size: (100, 25), position: (15, 432))]
    binary_label: nwg::Label,

    #[nwg_control(text: "", size: (165, 23), position: (120, 430), placeholder_text: Some("(Default)"))]
    binary_input: nwg::TextInput,

    #[nwg_control(text: "Browse...", size: (70, 23), position: (290, 430))]
    #[nwg_events(OnButtonClick: [PreferencesDialog::on_browse_binary])]
    binary_browse: nwg::Button,

    // --- Buttons ---
    #[nwg_control(text: "Cancel", size: (80, 30), position: (245, 480))]
    #[nwg_events(OnButtonClick: [PreferencesDialog::on_cancel])]
    cancel_btn: nwg::Button,

    #[nwg_control(text: "Save", size: (80, 30), position: (335, 480))]
    #[nwg_events(OnButtonClick: [PreferencesDialog::on_save])]
    save_btn: nwg::Button,

    // --- Non-NWG fields ---
    done: Cell<bool>,
    result: RefCell<Option<Settings>>,
}

impl PreferencesDialog {
    fn on_close(&self) {
        self.window.set_visible(false);
        self.done.set(true);
    }

    fn on_cancel(&self) {
        self.window.set_visible(false);
        self.done.set(true);
    }

    fn on_save(&self) {
        *self.result.borrow_mut() = Some(self.read_settings());
        self.window.set_visible(false);
        self.done.set(true);
    }

    fn on_mode_change(&self) {
        self.update_visibility();
    }

    fn on_tls_change(&self) {
        let tls = self.tls_check.check_state() == nwg::CheckBoxState::Checked;
        self.insecure_check.set_enabled(tls);
        if !tls {
            self.insecure_check.set_check_state(nwg::CheckBoxState::Unchecked);
        }
    }

    fn on_browse_key_file(&self) {
        let mut dialog: nwg::FileDialog = Default::default();
        let _ = nwg::FileDialog::builder()
            .title("Select Key File")
            .action(nwg::FileDialogAction::Open)
            .build(&mut dialog);

        if dialog.run(Some(&self.window)) {
            if let Ok(path) = dialog.get_selected_item() {
                self.key_file_input.set_text(&path.into_string().unwrap_or_default());
            }
        }
    }

    fn on_browse_binary(&self) {
        let mut dialog: nwg::FileDialog = Default::default();
        let _ = nwg::FileDialog::builder()
            .title("Select iroh-webproxy Binary")
            .action(nwg::FileDialogAction::Open)
            .build(&mut dialog);

        if dialog.run(Some(&self.window)) {
            if let Ok(path) = dialog.get_selected_item() {
                self.binary_input.set_text(&path.into_string().unwrap_or_default());
            }
        }
    }

    fn update_visibility(&self) {
        let show_client = matches!(self.mode_combo.selection(), Some(0) | Some(2));
        let show_server = matches!(self.mode_combo.selection(), Some(1) | Some(2));

        // Toggle visibility
        self.client_section.set_visible(show_client);
        self.http_port_label.set_visible(show_client);
        self.http_port_input.set_visible(show_client);
        self.https_port_label.set_visible(show_client);
        self.https_port_input.set_visible(show_client);
        self.self_sign_check.set_visible(show_client);
        self.bind_addr_label.set_visible(show_client);
        self.bind_addr_input.set_visible(show_client);
        self.host_suffix_label.set_visible(show_client);
        self.host_suffix_input.set_visible(show_client);

        self.server_section.set_visible(show_server);
        self.target_host_label.set_visible(show_server);
        self.target_host_input.set_visible(show_server);
        self.target_port_label.set_visible(show_server);
        self.target_port_input.set_visible(show_server);
        self.tls_check.set_visible(show_server);
        self.insecure_check.set_visible(show_server);
        self.key_file_label.set_visible(show_server);
        self.key_file_input.set_visible(show_server);
        self.key_file_browse.set_visible(show_server);

        // Reposition sections based on what's visible
        let base = 50i32;
        let client_block = 175i32; // height of client section + gap
        let server_block = 180i32; // height of server section + gap

        let sy = base + if show_client { client_block } else { 0 };
        let ay = sy + if show_server { server_block } else { 0 };

        // Server controls (offsets from section start)
        self.server_section.set_position(15, sy);
        self.target_host_label.set_position(15, sy + 27);
        self.target_host_input.set_position(120, sy + 25);
        self.target_port_label.set_position(15, sy + 57);
        self.target_port_input.set_position(120, sy + 55);
        self.tls_check.set_position(120, sy + 85);
        self.insecure_check.set_position(120, sy + 113);
        self.key_file_label.set_position(15, sy + 145);
        self.key_file_input.set_position(120, sy + 143);
        self.key_file_browse.set_position(290, sy + 143);

        // Advanced controls
        self.advanced_section.set_position(15, ay);
        self.binary_label.set_position(15, ay + 27);
        self.binary_input.set_position(120, ay + 25);
        self.binary_browse.set_position(290, ay + 25);

        // Buttons
        self.cancel_btn.set_position(245, ay + 75);
        self.save_btn.set_position(335, ay + 75);

        // Resize window to fit
        self.window.set_size(430, (ay + 75 + 50) as u32);
    }

    pub fn load_settings(&self, s: &Settings) {
        let mode_idx = match s.mode.as_str() {
            "client" => 0,
            "server" => 1,
            "both" => 2,
            _ => 0,
        };
        self.mode_combo.set_selection(Some(mode_idx));

        self.http_port_input.set_text(&s.http_port.to_string());
        self.https_port_input.set_text(&s.https_port.to_string());
        if s.self_sign {
            self.self_sign_check
                .set_check_state(nwg::CheckBoxState::Checked);
        } else {
            self.self_sign_check
                .set_check_state(nwg::CheckBoxState::Unchecked);
        }
        self.bind_addr_input.set_text(&s.ip_address);
        self.host_suffix_input.set_text(&s.host_suffix);

        self.target_host_input.set_text(&s.target_host);
        self.target_port_input.set_text(&s.target_port.to_string());
        if s.target_tls {
            self.tls_check
                .set_check_state(nwg::CheckBoxState::Checked);
        } else {
            self.tls_check
                .set_check_state(nwg::CheckBoxState::Unchecked);
        }
        if s.insecure {
            self.insecure_check
                .set_check_state(nwg::CheckBoxState::Checked);
        } else {
            self.insecure_check
                .set_check_state(nwg::CheckBoxState::Unchecked);
        }
        self.insecure_check.set_enabled(s.target_tls);
        self.key_file_input.set_text(&s.key_file_path);

        self.binary_input.set_text(&s.binary_path);
    }

    fn read_settings(&self) -> Settings {
        let mode = match self.mode_combo.selection() {
            Some(0) => "client",
            Some(1) => "server",
            Some(2) => "both",
            _ => "client",
        };

        Settings {
            mode: mode.to_string(),
            http_port: self.http_port_input.text().parse().unwrap_or(8080),
            https_port: self.https_port_input.text().parse().unwrap_or(8443),
            self_sign: self.self_sign_check.check_state() == nwg::CheckBoxState::Checked,
            ip_address: self.bind_addr_input.text(),
            host_suffix: self.host_suffix_input.text(),
            target_host: self.target_host_input.text(),
            target_port: self.target_port_input.text().parse().unwrap_or(8088),
            target_tls: self.tls_check.check_state() == nwg::CheckBoxState::Checked,
            insecure: self.insecure_check.check_state() == nwg::CheckBoxState::Checked,
            key_file_path: self.key_file_input.text(),
            binary_path: self.binary_input.text(),
            // These are preserved from the existing settings by the caller
            proxy_was_running: false,
            saved_server_node_id: String::new(),
        }
    }
}

/// Show the preferences dialog modally. Returns Some(new_settings) if saved, None if cancelled.
pub fn show_preferences(current: &Settings) -> Option<Settings> {
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    let app = PreferencesDialog::build_ui(Default::default()).expect("Failed to build preferences UI");
    app.load_settings(current);
    app.update_visibility();

    // Custom message loop that avoids PostQuitMessage (which would kill the outer tray loop)
    loop {
        if app.done.get() {
            break;
        }
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            let ret = PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE);
            if ret != 0 {
                if msg.message == WM_QUIT {
                    // Consume it here so it doesn't leak to the outer loop
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            } else {
                WaitMessage();
            }
        }
    }

    let result = app.result.borrow().clone();
    result
}

use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}

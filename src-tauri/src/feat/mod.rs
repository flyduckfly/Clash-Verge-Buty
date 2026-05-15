pub mod clash_patch;
pub mod system_proxy;
pub mod verge_patch;

pub use clash_patch::patch_clash;
pub use verge_patch::patch_verge;
//！
// feat mod 里的函数主要用于
// - hotkey 快捷键
// - timer 定时器
// - cmds 页面调用
//
use crate::config::*;
use crate::core::*;
use crate::log_err;
use crate::utils::resolve;
use anyhow::{bail, Result};
use serde_yaml::{Mapping, Value};
use tauri::{AppHandle, ClipboardManager, Manager};

// 打开面板
pub fn open_or_close_dashboard() {
    let handle = handle::Handle::global();
    let app_handle = handle.app_handle.lock();
    if let Some(app_handle) = app_handle.as_ref() {
        if let Some(window) = app_handle.get_window("main") {
            if let Ok(true) = window.is_focused() {
                let _ = window.close();
                return;
            }
        }
        resolve::create_window(app_handle);
    }
}

// 重启clash
pub fn restart_clash_core() {
    tauri::async_runtime::spawn(async {
        match CoreManager::global().run_core().await {
            Ok(_) => {
                handle::Handle::refresh_clash();
                handle::Handle::notice_message("set_config::ok", "ok");
            }
            Err(err) => {
                handle::Handle::notice_message("set_config::error", format!("{err}"));
                log::error!(target:"app", "{err}");
            }
        }
    });
}

// 切换模式 rule/global/direct/script mode
pub fn change_clash_mode(mode: String) {
    let mut mapping = Mapping::new();
    mapping.insert(Value::from("mode"), mode.clone().into());

    tauri::async_runtime::spawn(async move {
        log::debug!(target: "app", "change clash mode to {mode}");

        match clash_api::patch_configs(&mapping).await {
            Ok(_) => {
                // 更新订阅
                Config::clash().data().patch_config(mapping);

                if Config::clash().data().save_config().is_ok() {
                    handle::Handle::refresh_clash();
                    log_err!(handle::Handle::update_systray_part());
                }
            }
            Err(err) => log::error!(target: "app", "{err}"),
        }
    });
}

// 切换系统代理
pub fn toggle_system_proxy() {
    let enable = Config::verge().draft().enable_system_proxy;
    let enable = enable.unwrap_or(false);

    tauri::async_runtime::spawn(async move {
        match patch_verge(IVerge {
            enable_system_proxy: Some(!enable),
            ..IVerge::default()
        })
        .await
        {
            Ok(_) => handle::Handle::refresh_verge(),
            Err(err) => log::error!(target: "app", "{err}"),
        }
    });
}

// 切换tun模式
pub fn toggle_tun_mode() {
    let enable = Config::verge().data().enable_tun_mode;
    let enable = enable.unwrap_or(false);

    tauri::async_runtime::spawn(async move {
        match patch_verge(IVerge {
            enable_tun_mode: Some(!enable),
            ..IVerge::default()
        })
        .await
        {
            Ok(_) => handle::Handle::refresh_verge(),
            Err(err) => log::error!(target: "app", "{err}"),
        }
    });
}

/// 更新某个profile
/// 如果更新当前订阅就激活订阅
pub async fn update_profile(uid: String, option: Option<PrfOption>) -> Result<()> {
    let mut downloaded_remote_yaml = false;
    let url_opt = {
        let profiles = Config::profiles();
        let profiles = profiles.latest();
        let item = profiles.get_item(&uid)?;
        let is_remote = item.itype.as_ref().map_or(false, |s| s == "remote");

        if !is_remote {
            None // 直接更新
        } else if item.url.is_none() {
            bail!("failed to get the profile item url");
        } else {
            Some((item.url.clone().unwrap(), item.option.clone()))
        }
    };

    let should_update = match url_opt {
        Some((url, opt)) => {
            let merged_opt = PrfOption::merge(opt, option);
            let item = PrfItem::from_url(&url, None, None, merged_opt).await?;
            downloaded_remote_yaml = true;

            let profiles = Config::profiles();
            let mut profiles = profiles.latest();
            profiles.update_item(uid.clone(), item)?;

            Some(uid) == profiles.get_current()
        }
        None => true,
    };

    if should_update {
        if downloaded_remote_yaml {
            log::info!(target: "app", "remote profile yaml downloaded, regenerating runtime config through enhance chain");
        }
        update_core_config().await?;
    } else if downloaded_remote_yaml {
        log::info!(target: "app", "remote profile yaml downloaded for non-current profile, runtime config regeneration skipped");
    }

    Ok(())
}

/// 更新订阅
async fn update_core_config() -> Result<()> {
    log::info!(target: "app", "updating core config (generate/check/reload)");
    handle::Handle::emit_log("info", "[app] updating core config (generate/check/reload)");
    match CoreManager::global().update_config().await {
        Ok(_) => {
            handle::Handle::refresh_clash();
            handle::Handle::notice_message("set_config::ok", "ok");
            log::info!(target: "app", "core config updated successfully");
            handle::Handle::emit_log("info", "[app] core config updated successfully");
            Ok(())
        }
        Err(err) => {
            handle::Handle::notice_message("set_config::error", format!("{err}"));
            log::error!(target: "app", "core config update failed: {err}");
            handle::Handle::emit_log("error", format!("[app] core config update failed: {err}"));
            Err(err)
        }
    }
}

/// copy env variable
pub fn copy_clash_env(app_handle: &AppHandle) {
    let port = { Config::verge().latest().verge_mixed_port.unwrap_or(7897) };
    let http_proxy = format!("http://127.0.0.1:{}", port);
    let socks5_proxy = format!("socks5://127.0.0.1:{}", port);

    let sh =
        format!("export https_proxy={http_proxy} http_proxy={http_proxy} all_proxy={socks5_proxy}");
    let cmd: String = format!("set http_proxy={http_proxy} \n set https_proxy={http_proxy}");
    let ps: String = format!("$env:HTTP_PROXY=\"{http_proxy}\"; $env:HTTPS_PROXY=\"{http_proxy}\"");

    let mut cliboard = app_handle.clipboard_manager();

    let env_type = { Config::verge().latest().env_type.clone() };
    let env_type = match env_type {
        Some(env_type) => env_type,
        None => {
            #[cfg(not(target_os = "windows"))]
            let default = "bash";
            #[cfg(target_os = "windows")]
            let default = "powershell";

            default.to_string()
        }
    };
    match env_type.as_str() {
        "bash" => cliboard.write_text(sh).unwrap_or_default(),
        "cmd" => cliboard.write_text(cmd).unwrap_or_default(),
        "powershell" => cliboard.write_text(ps).unwrap_or_default(),
        _ => log::error!(target: "app", "copy_clash_env: Invalid env type! {env_type}"),
    };
}

pub async fn test_delay(url: String) -> Result<u32> {
    use tokio::time::{Duration, Instant};
    let mut builder = reqwest::ClientBuilder::new().use_rustls_tls().no_proxy();

    let port = Config::verge()
        .latest()
        .verge_mixed_port
        .unwrap_or(Config::clash().data().get_mixed_port());
    let tun_mode = Config::verge().latest().enable_tun_mode.unwrap_or(false);

    let proxy_scheme = format!("http://127.0.0.1:{port}");

    if !tun_mode {
        if let Ok(proxy) = reqwest::Proxy::http(&proxy_scheme) {
            builder = builder.proxy(proxy);
        }
        if let Ok(proxy) = reqwest::Proxy::https(&proxy_scheme) {
            builder = builder.proxy(proxy);
        }
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_scheme) {
            builder = builder.proxy(proxy);
        }
    }

    let request = builder
        .timeout(Duration::from_millis(10000))
        .build()?
        .get(url).header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
    let start = Instant::now();

    let response = request.send().await?;
    if response.status().is_success() {
        let delay = start.elapsed().as_millis() as u32;
        Ok(delay)
    } else {
        Ok(10000u32)
    }
}

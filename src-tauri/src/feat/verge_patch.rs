use crate::config::*;
use crate::core::*;
use crate::feat::update_core_config;
use anyhow::{bail, Result};

/// 修改verge的订阅
/// 一般都是一个个的修改
pub async fn patch_verge(patch: IVerge) -> Result<()> {
    Config::verge().draft().patch_config(patch.clone());

    let tun_mode = patch.enable_tun_mode;
    let auto_launch = patch.enable_auto_launch;
    let system_proxy = patch.enable_system_proxy;
    let proxy_bypass = patch.system_proxy_bypass;
    let language = patch.language;
    let port = patch.verge_mixed_port;
    let common_tray_icon = patch.common_tray_icon;
    let sysproxy_tray_icon = patch.sysproxy_tray_icon;
    let tun_tray_icon = patch.tun_tray_icon;

    match {
        #[cfg(target_os = "windows")]
        {
            let service_mode = patch.enable_service_mode;
            let latest_service_enabled = Config::verge()
                .latest()
                .enable_service_mode
                .unwrap_or(false);
            let service_effective_enabled = service_mode.unwrap_or(latest_service_enabled);
            if let Some(true) = tun_mode {
                if !service_effective_enabled {
                    bail!("Tun mode on Windows requires Service Mode. Please enable Service Mode first.");
                }

                crate::core::win_service::ensure_service_ready()
                    .await
                    .map_err(|err| {
                        anyhow::anyhow!("Tun mode on Windows requires clash-verge-service. {err}")
                    })?;
            }

            if service_mode.is_some() {
                log::debug!(target: "app", "change service mode to {}", service_mode.unwrap());

                Config::generate()?;
                CoreManager::global().run_core().await?;
            } else if tun_mode.is_some() {
                if service_effective_enabled {
                    log::info!(target: "app", "tun mode changed under Windows service mode, restarting core instead of hot reload");
                    Config::generate()?;
                    CoreManager::global().run_core().await?;
                } else {
                    update_core_config().await?;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        if tun_mode.is_some() {
            update_core_config().await?;
        }

        if auto_launch.is_some() {
            sysopt::Sysopt::global().update_launch()?;
        }
        if system_proxy.is_some() || proxy_bypass.is_some() || port.is_some() {
            sysopt::Sysopt::global().update_sysproxy()?;
            sysopt::Sysopt::global().guard_proxy();
        }

        if let Some(true) = patch.enable_proxy_guard {
            sysopt::Sysopt::global().guard_proxy();
        }

        if let Some(hotkeys) = patch.hotkeys {
            hotkey::Hotkey::global().update(hotkeys)?;
        }

        if language.is_some() {
            handle::Handle::update_systray()?;
        } else if system_proxy.is_some()
            || tun_mode.is_some()
            || common_tray_icon.is_some()
            || sysproxy_tray_icon.is_some()
            || tun_tray_icon.is_some()
        {
            handle::Handle::update_systray_part()?;
        }

        <Result<()>>::Ok(())
    } {
        Ok(()) => {
            Config::verge().apply();
            Config::verge().data().save_file()?;
            Ok(())
        }
        Err(err) => {
            Config::verge().discard();
            Err(err)
        }
    }
}

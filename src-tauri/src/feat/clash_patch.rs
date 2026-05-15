use crate::config::*;
use crate::core::*;
use crate::feat::update_core_config;
use crate::log_err;
use anyhow::{bail, Result};
use serde_yaml::Mapping;

/// 修改clash的订阅
pub async fn patch_clash(patch: Mapping) -> Result<()> {
    let has_tun_patch = patch.get("tun").is_some();
    if has_tun_patch {
        log::info!(target: "app", "patch clash tun config requested");
        handle::Handle::emit_log("info", "[tun] patch clash tun config requested");
    }
    Config::clash().draft().patch_config(patch.clone());

    match {
        let mixed_port = patch.get("mixed-port");
        let socks_port = patch.get("socks-port");
        let port = patch.get("port");
        let enable_random_port = Config::verge().latest().enable_random_port.unwrap_or(false);
        if mixed_port.is_some() && !enable_random_port {
            let changed = mixed_port.unwrap()
                != Config::verge()
                    .latest()
                    .verge_mixed_port
                    .unwrap_or(Config::clash().data().get_mixed_port());
            if changed {
                if let Some(port) = mixed_port.unwrap().as_u64() {
                    if !port_scanner::local_port_available(port as u16) {
                        Config::clash().discard();
                        bail!("port already in use");
                    }
                }
            }
        };

        if mixed_port.is_some()
            || socks_port.is_some()
            || port.is_some()
            || patch.get("secret").is_some()
            || patch.get("external-controller").is_some()
        {
            Config::generate()?;
            CoreManager::global().run_core().await?;
            handle::Handle::refresh_clash();
        }

        if mixed_port.is_some() {
            log_err!(sysopt::Sysopt::global().init_sysproxy());
        }

        if patch.get("mode").is_some() {
            log_err!(handle::Handle::update_systray_part());
        }

        if has_tun_patch {
            log::info!(target: "app", "tun config changed, reload core config");
            handle::Handle::emit_log("info", "[tun] tun config changed, reload core config");
            update_core_config().await?;
        }

        Config::runtime().latest().patch_config(patch);

        <Result<()>>::Ok(())
    } {
        Ok(()) => {
            Config::clash().apply();
            Config::clash().data().save_config()?;
            Ok(())
        }
        Err(err) => {
            Config::clash().discard();
            Err(err)
        }
    }
}

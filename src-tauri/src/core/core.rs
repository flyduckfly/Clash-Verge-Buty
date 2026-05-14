use super::{clash_api, logger::Logger};
use crate::log_err;
use crate::{config::*, utils::dirs};
use anyhow::{bail, Context, Result};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{fs, io::Write, sync::Arc, time::Duration};
use sysinfo::{Pid, System};
use tauri::api::process::{Command, CommandChild, CommandEvent};
use tokio::time::sleep;

#[derive(Debug)]
pub struct CoreManager {
    sidecar: Arc<Mutex<Option<CommandChild>>>,

    #[allow(unused)]
    use_service_mode: Arc<Mutex<bool>>,
}

impl CoreManager {
    fn read_pid_file_alive() -> Option<u32> {
        let pid = dirs::clash_pid_path()
            .ok()
            .and_then(|path| fs::read(path).ok())
            .and_then(|pid| String::from_utf8(pid).ok())
            .and_then(|pid| pid.trim().parse::<u32>().ok())?;
        let mut system = System::new();
        system.refresh_all();
        let process = system.process(Pid::from_u32(pid))?;
        if process.name().contains("clash") {
            return Some(pid);
        }
        None
    }

    pub fn global() -> &'static CoreManager {
        static CORE_MANAGER: OnceCell<CoreManager> = OnceCell::new();

        CORE_MANAGER.get_or_init(|| CoreManager {
            sidecar: Arc::new(Mutex::new(None)),
            use_service_mode: Arc::new(Mutex::new(false)),
        })
    }

    pub fn init(&self) -> Result<()> {
        // kill old clash process
        let _ = dirs::clash_pid_path()
            .and_then(|path| fs::read(path).map(|p| p.to_vec()).context(""))
            .and_then(|pid| String::from_utf8_lossy(&pid).parse().context(""))
            .map(|pid| {
                let mut system = System::new();
                system.refresh_all();
                if let Some(proc) = system.process(Pid::from_u32(pid)) {
                    if proc.name().contains("clash") {
                        log::debug!(target: "app", "kill old clash process");
                        proc.kill();
                    }
                }
            });

        tauri::async_runtime::spawn(async {
            // 启动clash
            log_err!(Self::global().run_core().await);
        });

        Ok(())
    }

    /// 检查订阅是否正确
    pub fn check_config(&self) -> Result<()> {
        let config_path = Config::generate_file(ConfigType::Check)?;
        let config_path = dirs::path_to_str(&config_path)?;

        let clash_core = { Config::verge().latest().clash_core.clone() };
        let clash_core = clash_core.unwrap_or("clash".into());

        let app_dir = dirs::app_home_dir()?;
        let app_dir = dirs::path_to_str(&app_dir)?;

        let output = Command::new_sidecar(clash_core)?
            .args(["-t", "-d", app_dir, "-f", config_path])
            .output()?;

        if !output.status.success() {
            let error = clash_api::parse_check_output(output.stdout.clone());
            let error = match !error.is_empty() {
                true => error,
                false => output.stdout.clone(),
            };
            Logger::global().set_log(output.stdout);
            bail!("{error}");
        }

        Ok(())
    }

    /// 启动核心
    pub async fn run_core(&self) -> Result<()> {
        let config_path = Config::generate_file(ConfigType::Run)?;
        log::info!(target: "app", "starting core with runtime config: {}", dirs::path_to_str(&config_path)?);
        self.log_tun_prerequisites();
        let previous_use_service_mode_lock = *self.use_service_mode.lock();
        let pid_file_pid = Self::read_pid_file_alive();

        #[allow(unused_mut)]
        let mut should_kill = match self.sidecar.lock().take() {
            Some(child) => {
                log::info!(target: "app", "run_core decision: stop_sidecar");
                let _ = child.kill();
                true
            }
            None => false,
        };

        #[cfg(target_os = "windows")]
        {
            use super::win_service;

            let desired_service_mode = Config::verge()
                .latest()
                .enable_service_mode
                .unwrap_or(false);
            let service_status = win_service::check_service().await?;
            let sidecar_pid = self.sidecar.lock().as_ref().map(|child| child.pid());
            log::info!(
                target: "app",
                "run_core decision input: desired_service_mode={}, previous_use_service_mode_lock={}, service_process_running={}, service_core_pid={:?}, sidecar_pid={:?}, pid_file_pid={:?}, current_runtime_config={}",
                desired_service_mode,
                previous_use_service_mode_lock,
                service_status.running,
                service_status.core_pid,
                sidecar_pid,
                pid_file_pid,
                dirs::path_to_str(&config_path)?
            );

            if service_status.core_managed {
                log::info!(target: "app", "run_core decision: stop_service_core");
                win_service::stop_core_by_service().await?;
                should_kill = true;
            }

            if should_kill {
                sleep(Duration::from_millis(500)).await;
            }

            *self.use_service_mode.lock() = desired_service_mode;
            if desired_service_mode {
                log::info!(target: "app", "run_core decision: start_service_core_or_reuse");
                let tun_enabled = Config::verge().latest().enable_tun_mode.unwrap_or(false);

                match (|| async {
                    win_service::ensure_service_ready().await?;
                    win_service::run_core_by_service(&config_path, true).await
                })()
                .await
                {
                    Ok(_) => return Ok(()),
                    Err(err) => {
                        log::error!(target: "app", "Service Mode failed; service could not start clash core. {err}");
                        if tun_enabled {
                            bail!(
                                "Tun mode requires a working clash-verge-service on Windows: {err}"
                            );
                        }
                        bail!("Service Mode failed; service could not start clash core. {err}");
                    }
                }
            }
        }

        // 这里得等一会儿
        if should_kill {
            sleep(Duration::from_millis(500)).await;
        }

        let app_dir = dirs::app_home_dir()?;
        let app_dir = dirs::path_to_str(&app_dir)?;

        let clash_core = { Config::verge().latest().clash_core.clone() };
        let clash_core = clash_core.unwrap_or("clash".into());
        let is_clash = clash_core == "clash";

        let config_path = dirs::path_to_str(&config_path)?;

        let args = match clash_core.as_str() {
            "clash-meta" => vec!["-d", app_dir, "-f", config_path],
            "clash-meta-alpha" => vec!["-d", app_dir, "-f", config_path],
            _ => vec!["-d", app_dir, "-f", config_path],
        };

        let cmd = Command::new_sidecar(clash_core)?;
        log::info!(target: "app", "run_core decision: start_sidecar");
        let (mut rx, cmd_child) = cmd.args(args).spawn()?;

        // 将pid写入文件中
        crate::log_err!((|| {
            let pid = cmd_child.pid();
            let path = dirs::clash_pid_path()?;
            fs::File::create(path)
                .context("failed to create the pid file")?
                .write(format!("{pid}").as_bytes())
                .context("failed to write pid to the file")?;
            <Result<()>>::Ok(())
        })());

        let mut sidecar = self.sidecar.lock();
        *sidecar = Some(cmd_child);
        drop(sidecar);

        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        if is_clash {
                            let stdout = clash_api::parse_log(line.clone());
                            log::info!(target: "app", "[clash]: {stdout}");
                        } else {
                            log::info!(target: "app", "[clash]: {line}");
                        };
                        Logger::global().set_log(line);
                    }
                    CommandEvent::Stderr(err) => {
                        // let stdout = clash_api::parse_log(err.clone());
                        log::error!(target: "app", "[clash]: {err}");
                        Logger::global().set_log(err);
                    }
                    CommandEvent::Error(err) => {
                        log::error!(target: "app", "[clash]: {err}");
                        Logger::global().set_log(err);
                    }
                    CommandEvent::Terminated(_) => {
                        log::info!(target: "app", "clash core terminated");
                        let _ = CoreManager::global().recover_core();
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    fn log_tun_prerequisites(&self) {
        let tun_enabled = Config::verge().latest().enable_tun_mode.unwrap_or(false);
        if !tun_enabled {
            return;
        }
        #[cfg(target_os = "windows")]
        {
            use deelevate::{PrivilegeLevel, Token};
            let service_mode = Config::verge()
                .latest()
                .enable_service_mode
                .unwrap_or(false);
            let privilege = Token::with_current_process()
                .ok()
                .and_then(|t| t.privilege_level().ok());
            let is_admin = matches!(privilege, Some(PrivilegeLevel::Elevated));
            if !service_mode {
                log::error!(target: "app", "Tun mode is enabled but service mode is disabled on Windows. This usually fails without admin/wintun permissions.");
                super::handle::Handle::emit_log(
                    "error",
                    "[service] Tun mode is enabled but service mode is disabled on Windows.",
                );
            } else {
                log::info!(target: "app", "Tun mode enabled on Windows with service mode.");
                super::handle::Handle::emit_log(
                    "info",
                    "[service] Tun mode enabled on Windows with service mode.",
                );
            }
            if !is_admin {
                log::warn!(target: "app", "Current process is not elevated. If service mode is unavailable, Tun setup may fail due to missing admin privileges/wintun route permissions.");
                super::handle::Handle::emit_log("warn", "[service] Current process is not elevated. Tun setup may fail due to missing admin privileges/wintun route permissions.");
            }
            log::info!(target: "app", "Windows Tun diagnostics: ensure clash-verge-service is active, wintun driver can be loaded, and firewall allows route/DNS hijack operations.");
            super::handle::Handle::emit_log("info", "[tun] Windows Tun diagnostics: ensure service active, wintun loadable, and firewall allows route/DNS hijack operations.");
        }
        #[cfg(target_os = "linux")]
        {
            if !Path::new("/dev/net/tun").exists() {
                log::error!(target: "app", "Tun mode requires /dev/net/tun on Linux, but it does not exist.");
            }
            log::info!(target: "app", "Tun mode on Linux requires CAP_NET_ADMIN and iptables/nftables permissions.");
        }
        #[cfg(target_os = "macos")]
        {
            log::info!(target: "app", "Tun mode on macOS requires network extension / route permissions.");
        }
    }

    /// 重启内核
    pub fn recover_core(&'static self) -> Result<()> {
        // 清空原来的sidecar值
        if let Some(sidecar) = self.sidecar.lock().take() {
            let _ = sidecar.kill();
        }

        tauri::async_runtime::spawn(async move {
            // 6秒之后再查看服务是否正常 (时间随便搞的)
            // terminated 可能是切换内核 (切换内核已经有500ms的延迟)
            sleep(Duration::from_millis(6666)).await;

            if self.sidecar.lock().is_none() {
                #[cfg(target_os = "windows")]
                {
                    let desired_service_mode = Config::verge()
                        .latest()
                        .enable_service_mode
                        .unwrap_or(false);
                    let previous_use_service_mode_lock = *self.use_service_mode.lock();
                    let pid_file_pid = Self::read_pid_file_alive();
                    let service_status = super::win_service::check_service().await.ok();
                    let service_running =
                        service_status.as_ref().map(|s| s.running).unwrap_or(false);
                    let service_core_pid = service_status.as_ref().and_then(|s| s.core_pid);
                    let sidecar_pid = self.sidecar.lock().as_ref().map(|c| c.pid());
                    log::info!(target: "app", "recover_core decision input: reason=sidecar_terminated, desired_service_mode={}, previous_use_service_mode_lock={}, service_process_running={}, service_core_pid={:?}, sidecar_pid={:?}, pid_file_pid={:?}", desired_service_mode, previous_use_service_mode_lock, service_running, service_core_pid, sidecar_pid, pid_file_pid);
                    if desired_service_mode || service_core_pid.is_some() {
                        log::info!(target: "app", "recover_core decision: skip");
                        return;
                    }
                }

                log::info!(target: "app", "recover_core decision: start_sidecar");

                // 重新启动app
                if let Err(err) = self.run_core().await {
                    log::error!(target: "app", "failed to recover clash core");
                    log::error!(target: "app", "{err}");

                    let _ = self.recover_core();
                }
            }
        });

        Ok(())
    }

    /// 停止核心运行
    pub fn stop_core(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        tauri::async_runtime::block_on(async move {
            let desired_service_mode = Config::verge()
                .latest()
                .enable_service_mode
                .unwrap_or(false);
            let service_status = super::win_service::check_service().await.ok();
            let service_core_pid = service_status.as_ref().and_then(|s| s.core_pid);
            log::info!(target: "app", "stop_core decision input: desired_service_mode={}, service_process_running={}, service_core_pid={:?}", desired_service_mode, service_status.as_ref().map(|s| s.running).unwrap_or(false), service_core_pid);
            if service_core_pid.is_some() {
                log::info!(target: "app", "stop_core decision: stop_service_core");
                log_err!(super::win_service::stop_core_by_service().await);
            }
        });

        let mut sidecar = self.sidecar.lock();
        if let Some(child) = sidecar.take() {
            log::info!(target: "app", "stop_core decision: stop_sidecar");
            let _ = child.kill();
        }
        Ok(())
    }

    /// 切换核心
    pub async fn change_core(&self, clash_core: Option<String>) -> Result<()> {
        let clash_core = clash_core.ok_or(anyhow::anyhow!("clash core is null"))?;
        const CLASH_CORES: [&str; 2] = ["clash-meta", "clash-meta-alpha"];

        if !CLASH_CORES.contains(&clash_core.as_str()) {
            bail!("invalid clash core name \"{clash_core}\"");
        }

        log::debug!(target: "app", "change core to `{clash_core}`");

        Config::verge().draft().clash_core = Some(clash_core);

        // 更新订阅
        Config::generate()?;

        self.check_config()?;

        // 清掉旧日志
        Logger::global().clear_log();

        match self.run_core().await {
            Ok(_) => {
                Config::verge().apply();
                Config::runtime().apply();
                log_err!(Config::verge().latest().save_file());
                Ok(())
            }
            Err(err) => {
                Config::verge().discard();
                Config::runtime().discard();
                Err(err)
            }
        }
    }

    /// 更新proxies那些
    /// 如果涉及端口和外部控制则需要重启
    pub async fn update_config(&self) -> Result<()> {
        log::debug!(target: "app", "try to update clash config");

        // 更新订阅
        Config::generate()?;

        // 检查订阅是否正常
        self.check_config()?;

        // 更新运行时订阅
        let path = Config::generate_file(ConfigType::Run)?;
        let path = dirs::path_to_str(&path)?;

        // 发送请求 发送5次
        for i in 0..5 {
            match clash_api::put_configs(path).await {
                Ok(_) => break,
                Err(err) => {
                    if i < 4 {
                        log::info!(target: "app", "{err}");
                    } else {
                        bail!(err);
                    }
                }
            }
            sleep(Duration::from_millis(250)).await;
        }

        Ok(())
    }
}

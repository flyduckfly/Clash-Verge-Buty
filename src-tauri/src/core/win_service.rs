#![cfg(target_os = "windows")]

use crate::config::Config;
use crate::utils::dirs;
use anyhow::{bail, Context, Result};
use deelevate::{PrivilegeLevel, Token};
use runas::Command as RunasCommand;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env::current_exe, process::Command as StdCommand};
use tokio::{
    net::lookup_host,
    time::{sleep, timeout},
};

const SERVICE_URL: &str = "http://127.0.0.1:33211";
const EXTERNAL_CONTROLLER_URL: &str = "http://127.0.0.1:9097/configs";
const SERVICE_NAME: &str = "clash-verge-service";
const SERVICE_BINARY: &str = "clash-verge-service.exe";
const INSTALL_HELPER: &str = "install-service.exe";
const UNINSTALL_HELPER: &str = "uninstall-service.exe";

fn read_tun_enable_from_runtime_file(config_file: &str) -> Option<bool> {
    let content = std::fs::read_to_string(config_file).ok()?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content).ok()?;
    yaml.get("tun")
        .and_then(YamlValue::as_mapping)
        .and_then(|m| m.get(YamlValue::from("enable")))
        .and_then(YamlValue::as_bool)
}

#[derive(Debug)]
struct ScResult {
    code: i32,
    stdout: String,
    stderr: String,
}

fn sc(args: &[&str]) -> Result<ScResult> {
    let output = StdCommand::new("sc.exe")
        .args(args)
        .creation_flags(0x08000000)
        .output()?;
    Ok(ScResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn service_exists(name: &str) -> bool {
    sc(&["query", name]).map(|r| r.code == 0).unwrap_or(false)
}

fn start_service_process() -> Result<()> {
    let start = sc(&["start", SERVICE_NAME])?;
    if start.code == 0 {
        return Ok(());
    }
    let out = format!("{}\n{}", start.stdout, start.stderr).to_ascii_uppercase();
    if start.code == 1056
        || out.contains("1056")
        || out.contains("INSTANCE OF THE SERVICE IS ALREADY RUNNING")
    {
        log::info!(target: "app", "service already running, continue checking API readiness.");
        return Ok(());
    }
    bail!("failed to start service process. expected service name: {SERVICE_NAME}; service binary: {SERVICE_BINARY}; install helper: {INSTALL_HELPER}; uninstall helper: {UNINSTALL_HELPER}; sc.exe start exit code: {}; stdout: {}; stderr: {}", start.code, start.stdout, start.stderr)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceStateHint {
    Running,
    StartPending,
    Other,
}

fn query_service_state() -> Result<ServiceStateHint> {
    let r = sc(&["query", SERVICE_NAME])?;
    if r.code != 0 {
        return Ok(ServiceStateHint::Other);
    }
    let out = r.stdout.to_ascii_uppercase();
    if out.contains("RUNNING") {
        Ok(ServiceStateHint::Running)
    } else if out.contains("START_PENDING") {
        Ok(ServiceStateHint::StartPending)
    } else {
        Ok(ServiceStateHint::Other)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponseBody {
    pub core_type: Option<String>,
    pub pid: Option<u32>,
    pub running: Option<bool>,
    pub bin_path: String,
    pub config_dir: String,
    pub config_file: Option<String>,
    pub log_file: String,
}

fn same_windows_path(a: &str, b: &str) -> bool {
    fn normalize(path: &str) -> String {
        path.replace('/', "\\").to_ascii_lowercase()
    }
    let canonicalized = |p: &str| {
        std::fs::canonicalize(Path::new(p))
            .ok()
            .map(|c| normalize(&c.to_string_lossy()))
    };

    match (canonicalized(a), canonicalized(b)) {
        (Some(left), Some(right)) => left == right,
        _ => normalize(a) == normalize(b),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonResponse {
    pub code: u64,
    pub msg: String,
    pub data: Option<ResponseBody>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthData {
    pub service: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthResponse {
    pub code: u64,
    pub msg: String,
    pub data: Option<HealthData>,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfigsTun {
    enable: Option<bool>,
    stack: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfigs {
    tun: Option<RuntimeConfigsTun>,
    mode: Option<String>,
}

fn encode_url_path_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub api_ready: bool,
    pub core_managed: bool,
    pub core_pid: Option<u32>,
    pub service_name: String,
    pub message: String,
}

pub async fn install_service() -> Result<()> {
    let binary_path = dirs::service_path()?;
    let install_path = binary_path.with_file_name(INSTALL_HELPER);
    if !install_path.exists() {
        bail!("installer exe not found: {}", INSTALL_HELPER);
    }
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;
    let status = match level {
        PrivilegeLevel::NotPrivileged => RunasCommand::new(install_path).show(false).status()?,
        _ => StdCommand::new(install_path)
            .creation_flags(0x08000000)
            .status()?,
    };
    if !status.success() {
        bail!(
            "failed to install service with status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub async fn uninstall_service() -> Result<()> {
    let binary_path = dirs::service_path()?;
    let uninstall_path = binary_path.with_file_name(UNINSTALL_HELPER);
    if !uninstall_path.exists() {
        bail!("uninstaller exe not found: {}", UNINSTALL_HELPER);
    }
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;
    let status = match level {
        PrivilegeLevel::NotPrivileged => RunasCommand::new(uninstall_path).show(false).status()?,
        _ => StdCommand::new(uninstall_path)
            .creation_flags(0x08000000)
            .status()?,
    };
    if !status.success() {
        bail!(
            "failed to uninstall service with status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub async fn check_service() -> Result<ServiceStatus> {
    let installed = service_exists(SERVICE_NAME);
    let running = installed
        && query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running;
    let health = get_service_health().await.ok();
    let api_ready = health.as_ref().map(|h| h.code == 0).unwrap_or(false);
    let clash = if api_ready {
        get_service_clash_state().await.ok()
    } else {
        None
    };
    let core_pid = clash
        .as_ref()
        .and_then(|s| s.data.as_ref())
        .and_then(|d| d.pid);
    let core_managed = core_pid.is_some();
    let message = if !installed {
        "service not installed.".to_string()
    } else if !running {
        "service installed but stopped.".to_string()
    } else if !api_ready {
        "service running, API not ready.".to_string()
    } else if !core_managed {
        "service running, API ready, core not managed by service.".to_string()
    } else {
        format!(
            "service running, API ready, core managed by service (pid {}).",
            core_pid.unwrap()
        )
    };
    Ok(ServiceStatus {
        installed,
        running,
        api_ready,
        core_managed,
        core_pid,
        service_name: SERVICE_NAME.to_string(),
        message,
    })
}

pub async fn ensure_service_ready() -> Result<()> {
    if query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running
        && get_service_health()
            .await
            .map(|h| h.code == 0)
            .unwrap_or(false)
    {
        return Ok(());
    }

    start_service_process()?;
    let timeout = Duration::from_secs(15);
    let started = std::time::Instant::now();

    loop {
        if query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running
            && get_service_health()
                .await
                .map(|h| h.code == 0)
                .unwrap_or(false)
        {
            return Ok(());
        }

        let state = query_service_state().unwrap_or(ServiceStateHint::Other);
        if started.elapsed() >= timeout {
            if state == ServiceStateHint::StartPending {
                bail!("Windows service is stuck in StartPending and API 127.0.0.1:33211 is not ready.");
            }
            bail!("service API 127.0.0.1:33211 is not ready after start timeout; current service state: {:?}", state);
        }

        sleep(Duration::from_millis(500)).await;
    }
}

pub(super) async fn run_core_by_service(config_file: &PathBuf, allow_reuse: bool) -> Result<()> {
    ensure_service_ready().await?;
    let status = check_service().await?;
    let clash_core = Config::verge()
        .latest()
        .clash_core
        .clone()
        .unwrap_or("clash".into());
    let clash_bin = format!("{clash_core}.exe");
    let bin_path_buf = current_exe()?.with_file_name(clash_bin);
    let config_dir_buf = dirs::app_home_dir()?;
    let log_path_buf = dirs::service_log_file()?;
    let bin_path = dirs::path_to_str(&bin_path_buf)?;
    let config_dir = dirs::path_to_str(&config_dir_buf)?;
    let log_path = dirs::path_to_str(&log_path_buf)?;
    let config_file = dirs::path_to_str(config_file)?;
    let existing = get_service_clash_state().await.ok();
    let compare = existing
        .as_ref()
        .and_then(|resp| resp.data.as_ref())
        .map(|d| {
            let compare_core_type = d.core_type.as_deref() == Some(clash_core.as_str());
            let compare_bin_path = same_windows_path(&d.bin_path, bin_path);
            let compare_config_dir = same_windows_path(&d.config_dir, config_dir);
            let compare_config_file = d
                .config_file
                .as_deref()
                .map(|existing_config_file| same_windows_path(existing_config_file, config_file))
                .unwrap_or(false);
            let compare_config_file_reason = if d.config_file.is_none() {
                "config_file_missing"
            } else {
                "ok"
            };
            let same_runtime = d.pid.is_some()
                && compare_core_type
                && compare_bin_path
                && compare_config_dir
                && compare_config_file;
            (
                same_runtime,
                compare_core_type,
                compare_bin_path,
                compare_config_dir,
                compare_config_file,
                compare_config_file_reason,
            )
        })
        .unwrap_or((false, false, false, false, false, "no_existing_state"));
    let (
        same_runtime,
        compare_core_type,
        compare_bin_path,
        compare_config_dir,
        compare_config_file,
        compare_config_file_reason,
    ) = compare;
    log::info!(
        target: "app",
        "run_core_by_service decision input: allow_reuse={}, same_runtime={}, compare_core_type={}, compare_bin_path={}, compare_config_dir={}, compare_config_file={}, compare_config_file_reason={}, ignored_log_file_for_reuse=true",
        allow_reuse,
        same_runtime,
        compare_core_type,
        compare_bin_path,
        compare_config_dir,
        compare_config_file,
        compare_config_file_reason
    );
    if allow_reuse && status.core_managed && same_runtime {
        log::info!(target: "app", "run_core_by_service decision: reuse_service_core, service_process_running={}, service_core_pid={:?}, current_runtime_config={}", status.running, status.core_pid, config_file);
        return Ok(());
    }
    if status.core_managed {
        log::info!(target: "app", "run_core_by_service decision: restart_service_core, service_process_running={}, old_service_core_pid={:?}, current_runtime_config={}", status.running, status.core_pid, config_file);
        stop_core_by_service().await?;
        sleep(Duration::from_secs(1)).await;
    }
    let file_tun_enable = read_tun_enable_from_runtime_file(config_file);
    let mut map = HashMap::new();
    map.insert("core_type", clash_core.as_str());
    map.insert("bin_path", bin_path);
    map.insert("config_dir", config_dir);
    map.insert("config_file", config_file);
    map.insert("log_file", log_path);
    log::info!(target: "app", "run_core_by_service decision: start_service_core");
    log::info!(target: "app", "service mode enabled: calling /start_clash");
    log::info!(target: "app", "start_clash request field summary: core_type={clash_core}, bin_path_exists={}, config_dir_exists={}, config_file={}, log_file={}, config_tun_enable={:?}", bin_path_buf.exists(), config_dir_buf.exists(), config_file, log_path, file_tun_enable);
    let res = reqwest::ClientBuilder::new()
        .no_proxy()
        .build()?
        .post(format!("{SERVICE_URL}/start_clash"))
        .json(&map)
        .send()
        .await?
        .json::<JsonResponse>()
        .await
        .context("failed to connect to the clash-verge-service")?;
    log::info!(target: "app", "start_clash response: code={}, msg={}", res.code, res.msg);
    if res.code != 0 {
        bail!(res.msg);
    }
    log::info!(target: "app", "waiting for /get_clash pid");
    let mut core_pid = None;
    for _ in 0..20 {
        if let Ok(state) = get_service_clash_state().await {
            let pid = state.data.as_ref().and_then(|d| d.pid);
            if pid.is_some() {
                core_pid = pid;
                break;
            }
        }
        sleep(Duration::from_millis(300)).await;
    }
    if core_pid.is_none() {
        bail!("service did not start clash core; /get_clash has no pid");
    }

    log::info!(target: "app", "waiting 9097 ready");
    let client = reqwest::ClientBuilder::new().no_proxy().build()?;
    for _ in 0..20 {
        if let Ok(resp) = client.get(EXTERNAL_CONTROLLER_URL).send().await {
            if resp.status().is_success() {
                let cfg = resp.json::<RuntimeConfigs>().await.ok();
                if let Some(cfg) = cfg {
                    let tun_enabled = cfg.tun.as_ref().and_then(|t| t.enable).unwrap_or(false);
                    let tun_stack = cfg
                        .tun
                        .as_ref()
                        .and_then(|t| t.stack.clone())
                        .unwrap_or_default();
                    log::info!(target: "app", "9097 ready success; runtime mode={:?}, tun_enable={}, tun_stack={}", cfg.mode, tun_enabled, tun_stack);
                    if tun_enabled && !tun_stack.eq_ignore_ascii_case("gvisor") {
                        log::warn!(target: "app", "TUN stack is not gVisor in runtime config: {}", tun_stack);
                    }
                }
                return Ok(());
            }
        }
        sleep(Duration::from_millis(300)).await;
    }
    log::error!(target: "app", "9097 ready failure");
    bail!("service started clash core (pid {:?}) but external-controller 127.0.0.1:9097 is not ready. service log file: {}", core_pid, log_path)
}

pub(super) async fn stop_core_by_service() -> Result<()> {
    let status = check_service().await.ok();
    log::info!(target: "app", "stop_clash input: service_process_running={}, service_core_pid={:?}", status.as_ref().map(|s| s.running).unwrap_or(false), status.as_ref().and_then(|s| s.core_pid));
    let res = reqwest::ClientBuilder::new()
        .no_proxy()
        .build()?
        .post(format!("{SERVICE_URL}/stop_clash"))
        .send()
        .await?
        .json::<JsonResponse>()
        .await
        .context("failed to connect to the clash-verge-service")?;
    if res.code != 0 {
        bail!(res.msg);
    }
    log::info!(target: "app", "stop_clash decision: stop_service_core");
    Ok(())
}

use crate::config::Config;
use crate::utils::dirs;
use anyhow::{bail, Context, Result};
use deelevate::{PrivilegeLevel, Token};
use runas::Command as RunasCommand;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env::current_exe, process::Command as StdCommand};
use tokio::{
    net::lookup_host,
    time::{sleep, timeout},
};

const SERVICE_URL: &str = "http://127.0.0.1:33211";
const EXTERNAL_CONTROLLER_URL: &str = "http://127.0.0.1:9097/configs";
const SERVICE_NAME: &str = "clash-verge-service";
const SERVICE_BINARY: &str = "clash-verge-service.exe";
const INSTALL_HELPER: &str = "install-service.exe";
const UNINSTALL_HELPER: &str = "uninstall-service.exe";

fn read_tun_enable_from_runtime_file(config_file: &str) -> Option<bool> {
    let content = std::fs::read_to_string(config_file).ok()?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content).ok()?;
    yaml.get("tun")
        .and_then(YamlValue::as_mapping)
        .and_then(|m| m.get(YamlValue::from("enable")))
        .and_then(YamlValue::as_bool)
}

#[derive(Debug)]
struct ScResult {
    code: i32,
    stdout: String,
    stderr: String,
}

fn sc(args: &[&str]) -> Result<ScResult> {
    let output = StdCommand::new("sc.exe")
        .args(args)
        .creation_flags(0x08000000)
        .output()?;
    Ok(ScResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn service_exists(name: &str) -> bool {
    sc(&["query", name]).map(|r| r.code == 0).unwrap_or(false)
}

fn start_service_process() -> Result<()> {
    let start = sc(&["start", SERVICE_NAME])?;
    if start.code == 0 {
        return Ok(());
    }
    let out = format!("{}\n{}", start.stdout, start.stderr).to_ascii_uppercase();
    if start.code == 1056
        || out.contains("1056")
        || out.contains("INSTANCE OF THE SERVICE IS ALREADY RUNNING")
    {
        log::info!(target: "app", "service already running, continue checking API readiness.");
        return Ok(());
    }
    bail!("failed to start service process. expected service name: {SERVICE_NAME}; service binary: {SERVICE_BINARY}; install helper: {INSTALL_HELPER}; uninstall helper: {UNINSTALL_HELPER}; sc.exe start exit code: {}; stdout: {}; stderr: {}", start.code, start.stdout, start.stderr)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceStateHint {
    Running,
    StartPending,
    Other,
}

fn query_service_state() -> Result<ServiceStateHint> {
    let r = sc(&["query", SERVICE_NAME])?;
    if r.code != 0 {
        return Ok(ServiceStateHint::Other);
    }
    let out = r.stdout.to_ascii_uppercase();
    if out.contains("RUNNING") {
        Ok(ServiceStateHint::Running)
    } else if out.contains("START_PENDING") {
        Ok(ServiceStateHint::StartPending)
    } else {
        Ok(ServiceStateHint::Other)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponseBody {
    pub core_type: Option<String>,
    pub pid: Option<u32>,
    pub running: Option<bool>,
    pub bin_path: String,
    pub config_dir: String,
    pub config_file: Option<String>,
    pub log_file: String,
}

fn same_windows_path(a: &str, b: &str) -> bool {
    fn normalize(path: &str) -> String {
        path.replace('/', "\\").to_ascii_lowercase()
    }
    let canonicalized = |p: &str| {
        std::fs::canonicalize(Path::new(p))
            .ok()
            .map(|c| normalize(&c.to_string_lossy()))
    };

    match (canonicalized(a), canonicalized(b)) {
        (Some(left), Some(right)) => left == right,
        _ => normalize(a) == normalize(b),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonResponse {
    pub code: u64,
    pub msg: String,
    pub data: Option<ResponseBody>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthData {
    pub service: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthResponse {
    pub code: u64,
    pub msg: String,
    pub data: Option<HealthData>,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfigsTun {
    enable: Option<bool>,
    stack: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfigs {
    tun: Option<RuntimeConfigsTun>,
    mode: Option<String>,
}

fn encode_url_path_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub api_ready: bool,
    pub core_managed: bool,
    pub core_pid: Option<u32>,
    pub service_name: String,
    pub message: String,
}

pub async fn install_service() -> Result<()> {
    let binary_path = dirs::service_path()?;
    let install_path = binary_path.with_file_name(INSTALL_HELPER);
    if !install_path.exists() {
        bail!("installer exe not found: {}", INSTALL_HELPER);
    }
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;
    let status = match level {
        PrivilegeLevel::NotPrivileged => RunasCommand::new(install_path).show(false).status()?,
        _ => StdCommand::new(install_path)
            .creation_flags(0x08000000)
            .status()?,
    };
    if !status.success() {
        bail!(
            "failed to install service with status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub async fn uninstall_service() -> Result<()> {
    let binary_path = dirs::service_path()?;
    let uninstall_path = binary_path.with_file_name(UNINSTALL_HELPER);
    if !uninstall_path.exists() {
        bail!("uninstaller exe not found: {}", UNINSTALL_HELPER);
    }
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;
    let status = match level {
        PrivilegeLevel::NotPrivileged => RunasCommand::new(uninstall_path).show(false).status()?,
        _ => StdCommand::new(uninstall_path)
            .creation_flags(0x08000000)
            .status()?,
    };
    if !status.success() {
        bail!(
            "failed to uninstall service with status {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub async fn check_service() -> Result<ServiceStatus> {
    let installed = service_exists(SERVICE_NAME);
    let running = installed
        && query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running;
    let health = get_service_health().await.ok();
    let api_ready = health.as_ref().map(|h| h.code == 0).unwrap_or(false);
    let clash = if api_ready {
        get_service_clash_state().await.ok()
    } else {
        None
    };
    let core_pid = clash
        .as_ref()
        .and_then(|s| s.data.as_ref())
        .and_then(|d| d.pid);
    let core_managed = core_pid.is_some();
    let message = if !installed {
        "service not installed.".to_string()
    } else if !running {
        "service installed but stopped.".to_string()
    } else if !api_ready {
        "service running, API not ready.".to_string()
    } else if !core_managed {
        "service running, API ready, core not managed by service.".to_string()
    } else {
        format!(
            "service running, API ready, core managed by service (pid {}).",
            core_pid.unwrap()
        )
    };
    Ok(ServiceStatus {
        installed,
        running,
        api_ready,
        core_managed,
        core_pid,
        service_name: SERVICE_NAME.to_string(),
        message,
    })
}

pub async fn ensure_service_ready() -> Result<()> {
    if query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running
        && get_service_health()
            .await
            .map(|h| h.code == 0)
            .unwrap_or(false)
    {
        return Ok(());
    }

    start_service_process()?;
    let timeout = Duration::from_secs(15);
    let started = std::time::Instant::now();

    loop {
        if query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running
            && get_service_health()
                .await
                .map(|h| h.code == 0)
                .unwrap_or(false)
        {
            return Ok(());
        }

        let state = query_service_state().unwrap_or(ServiceStateHint::Other);
        if started.elapsed() >= timeout {
            if state == ServiceStateHint::StartPending {
                bail!("Windows service is stuck in StartPending and API 127.0.0.1:33211 is not ready.");
            }
            bail!("service API 127.0.0.1:33211 is not ready after start timeout; current service state: {:?}", state);
        }

        sleep(Duration::from_millis(500)).await;
    }
}

pub(super) async fn run_core_by_service(config_file: &PathBuf, allow_reuse: bool) -> Result<()> {
    ensure_service_ready().await?;
    let status = check_service().await?;
    let clash_core = Config::verge()
        .latest()
        .clash_core
        .clone()
        .unwrap_or("clash".into());
    let clash_bin = format!("{clash_core}.exe");
    let bin_path_buf = current_exe()?.with_file_name(clash_bin);
    let config_dir_buf = dirs::app_home_dir()?;
    let log_path_buf = dirs::service_log_file()?;
    let bin_path = dirs::path_to_str(&bin_path_buf)?;
    let config_dir = dirs::path_to_str(&config_dir_buf)?;
    let log_path = dirs::path_to_str(&log_path_buf)?;
    let config_file = dirs::path_to_str(config_file)?;
    let existing = get_service_clash_state().await.ok();
    let compare = existing
        .as_ref()
        .and_then(|resp| resp.data.as_ref())
        .map(|d| {
            let compare_core_type = d.core_type.as_deref() == Some(clash_core.as_str());
            let compare_bin_path = same_windows_path(&d.bin_path, bin_path);
            let compare_config_dir = same_windows_path(&d.config_dir, config_dir);
            let compare_config_file = d
                .config_file
                .as_deref()
                .map(|existing_config_file| same_windows_path(existing_config_file, config_file))
                .unwrap_or(false);
            let compare_config_file_reason = if d.config_file.is_none() {
                "config_file_missing"
            } else {
                "ok"
            };
            let same_runtime = d.pid.is_some()
                && compare_core_type
                && compare_bin_path
                && compare_config_dir
                && compare_config_file;
            (
                same_runtime,
                compare_core_type,
                compare_bin_path,
                compare_config_dir,
                compare_config_file,
                compare_config_file_reason,
            )
        })
        .unwrap_or((false, false, false, false, false, "no_existing_state"));
    let (
        same_runtime,
        compare_core_type,
        compare_bin_path,
        compare_config_dir,
        compare_config_file,
        compare_config_file_reason,
    ) = compare;
    log::info!(
        target: "app",
        "run_core_by_service decision input: allow_reuse={}, same_runtime={}, compare_core_type={}, compare_bin_path={}, compare_config_dir={}, compare_config_file={}, compare_config_file_reason={}, ignored_log_file_for_reuse=true",
        allow_reuse,
        same_runtime,
        compare_core_type,
        compare_bin_path,
        compare_config_dir,
        compare_config_file,
        compare_config_file_reason
    );
    if allow_reuse && status.core_managed && same_runtime {
        log::info!(target: "app", "run_core_by_service decision: reuse_service_core, service_process_running={}, service_core_pid={:?}, current_runtime_config={}", status.running, status.core_pid, config_file);
        return Ok(());
    }
    if status.core_managed {
        log::info!(target: "app", "run_core_by_service decision: restart_service_core, service_process_running={}, old_service_core_pid={:?}, current_runtime_config={}", status.running, status.core_pid, config_file);
        stop_core_by_service().await?;
        sleep(Duration::from_secs(1)).await;
    }
    let file_tun_enable = read_tun_enable_from_runtime_file(config_file);
    let mut map = HashMap::new();
    map.insert("core_type", clash_core.as_str());
    map.insert("bin_path", bin_path);
    map.insert("config_dir", config_dir);
    map.insert("config_file", config_file);
    map.insert("log_file", log_path);
    log::info!(target: "app", "run_core_by_service decision: start_service_core");
    log::info!(target: "app", "service mode enabled: calling /start_clash");
    log::info!(target: "app", "start_clash request field summary: core_type={clash_core}, bin_path_exists={}, config_dir_exists={}, config_file={}, log_file={}, config_tun_enable={:?}", bin_path_buf.exists(), config_dir_buf.exists(), config_file, log_path, file_tun_enable);
    let res = reqwest::ClientBuilder::new()
        .no_proxy()
        .build()?
        .post(format!("{SERVICE_URL}/start_clash"))
        .json(&map)
        .send()
        .await?
        .json::<JsonResponse>()
        .await
        .context("failed to connect to the clash-verge-service")?;
    log::info!(target: "app", "start_clash response: code={}, msg={}", res.code, res.msg);
    if res.code != 0 {
        bail!(res.msg);
    }
    log::info!(target: "app", "waiting for /get_clash pid");
    let mut core_pid = None;
    for _ in 0..20 {
        if let Ok(state) = get_service_clash_state().await {
            let pid = state.data.as_ref().and_then(|d| d.pid);
            if pid.is_some() {
                core_pid = pid;
                break;
            }
        }
        sleep(Duration::from_millis(300)).await;
    }
    if core_pid.is_none() {
        bail!("service did not start clash core; /get_clash has no pid");
    }

    log::info!(target: "app", "waiting 9097 ready");
    let client = reqwest::ClientBuilder::new().no_proxy().build()?;
    for _ in 0..20 {
        if let Ok(resp) = client.get(EXTERNAL_CONTROLLER_URL).send().await {
            if resp.status().is_success() {
                let cfg = resp.json::<RuntimeConfigs>().await.ok();
                if let Some(cfg) = cfg {
                    let tun_enabled = cfg.tun.as_ref().and_then(|t| t.enable).unwrap_or(false);
                    let tun_stack = cfg
                        .tun
                        .as_ref()
                        .and_then(|t| t.stack.clone())
                        .unwrap_or_default();
                    log::info!(target: "app", "9097 ready success; runtime mode={:?}, tun_enable={}, tun_stack={}", cfg.mode, tun_enabled, tun_stack);
                    if tun_enabled && !tun_stack.eq_ignore_ascii_case("gvisor") {
                        log::warn!(target: "app", "TUN stack is not gVisor in runtime config: {}", tun_stack);
                    }
                }
                return Ok(());
            }
        }
        sleep(Duration::from_millis(300)).await;
    }
    log::error!(target: "app", "9097 ready failure");
    bail!("service started clash core (pid {:?}) but external-controller 127.0.0.1:9097 is not ready. service log file: {}", core_pid, log_path)
}

pub(super) async fn stop_core_by_service() -> Result<()> {
    let status = check_service().await.ok();
    log::info!(target: "app", "stop_clash input: service_process_running={}, service_core_pid={:?}", status.as_ref().map(|s| s.running).unwrap_or(false), status.as_ref().and_then(|s| s.core_pid));
    let res = reqwest::ClientBuilder::new()
        .no_proxy()
        .build()?
        .post(format!("{SERVICE_URL}/stop_clash"))
        .send()
        .await?
        .json::<JsonResponse>()
        .await
        .context("failed to connect to the clash-verge-service")?;
    if res.code != 0 {
        bail!(res.msg);
    }
    log::info!(target: "app", "stop_clash decision: stop_service_core");
    Ok(())
}

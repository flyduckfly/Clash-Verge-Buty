#![cfg(target_os = "windows")]

use crate::config::Config;
use crate::utils::dirs;
use anyhow::{bail, Context, Result};
use deelevate::{PrivilegeLevel, Token};
use runas::Command as RunasCommand;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::time::Duration;
use std::{env::current_exe, process::Command as StdCommand};
use tokio::{net::lookup_host, time::{sleep, timeout}};

const SERVICE_URL: &str = "http://127.0.0.1:33211";
const EXTERNAL_CONTROLLER_URL: &str = "http://127.0.0.1:9097/configs";
const SERVICE_NAME: &str = "clash-verge-service";
const SERVICE_BINARY: &str = "clash-verge-service.exe";
const INSTALL_HELPER: &str = "install-service.exe";
const UNINSTALL_HELPER: &str = "uninstall-service.exe";

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
    if start.code == 1056 || out.contains("1056") || out.contains("INSTANCE OF THE SERVICE IS ALREADY RUNNING") {
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
    pub log_file: String,
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

#[derive(Debug, Serialize, Clone)]
pub struct TunDiagnosticReport {
    pub tun_enabled: bool,
    pub service_core_managed: bool,
    pub core_api_ready: bool,
    pub dns_hijack_ok: bool,
    pub route_injected: bool,
    pub multiple_tun_adapters_detected: bool,
    pub adapter_candidates: Vec<String>,
    pub mode: Option<String>,
    pub outbound_group: Option<String>,
    pub selected_proxy: Option<String>,
    pub selected_proxy_type: Option<String>,
    pub route_decision: Option<String>,
    pub route_decision_type: Option<String>,
    pub selected_proxy_server_host: Option<String>,
    pub selected_proxy_server_port: Option<u16>,
    pub selected_proxy_is_direct: bool,
    pub selected_proxy_delay: Option<i64>,
    pub selected_proxy_reachable: Option<bool>,
    pub selected_proxy_delay_error: Option<String>,
    pub proxy_dns_failed: bool,
    pub proxy_dns_failed_hosts: Vec<String>,
    pub proxy_dns_failed_targets: Vec<String>,
    pub proxy_dns_failure_hint: Option<String>,
    pub system_dns_resolved_hosts: Vec<SystemDnsResolvedHost>,
    pub system_dns_status: Option<String>,
    pub dns_proxy_server_nameserver_status: Option<String>,
    pub dns_fake_ip_range: Option<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub dns_nameserver: Vec<String>,
    pub dns_respect_rules: Option<bool>,
    pub dns_enhanced_mode: Option<String>,
    pub service_log_file: Option<String>,
    pub service_log_summary: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SystemDnsResolvedHost {
    pub host: String,
    pub ips: Vec<String>,
    pub fake_ip_flags: Vec<bool>,
}

fn ipv4_to_u32(ip: std::net::Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn is_ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let (base, prefix_str) = match cidr.split_once('/') {
        Some(v) => v,
        None => return false,
    };
    let ip = match ip.parse::<std::net::Ipv4Addr>() { Ok(v) => v, Err(_) => return false };
    let base = match base.parse::<std::net::Ipv4Addr>() { Ok(v) => v, Err(_) => return false };
    let prefix: u32 = match prefix_str.parse::<u32>() { Ok(v) if v <= 32 => v, _ => return false };
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (ipv4_to_u32(ip) & mask) == (ipv4_to_u32(base) & mask)
}

fn is_likely_fake_ip(ip: &str, config_fake_ip_range: Option<&str>) -> bool {
    if let Some(range) = config_fake_ip_range.map(str::trim).filter(|v| !v.is_empty()) {
        if is_ipv4_in_cidr(ip, range) {
            return true;
        }
    }
    is_ipv4_in_cidr(ip, "198.18.0.0/15")
}

fn is_probably_domain(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_err()
}

fn classify_system_dns_status(system_dns_resolved_hosts: &[SystemDnsResolvedHost]) -> String {
    if system_dns_resolved_hosts.is_empty() {
        return "failed".to_string();
    }
    let mut has_fake = false;
    let mut has_real = false;
    for item in system_dns_resolved_hosts {
        for is_fake in &item.fake_ip_flags {
            if *is_fake {
                has_fake = true;
            } else {
                has_real = true;
            }
        }
    }
    match (has_fake, has_real) {
        (true, true) => "mixed".to_string(),
        (true, false) => "fake-ip".to_string(),
        (false, true) => "resolved".to_string(),
        (false, false) => "failed".to_string(),
    }
}

fn collect_string_array(v: Option<&JsonValue>) -> Vec<String> {
    v.and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).map(|x| x.to_string()).collect())
        .unwrap_or_default()
}

fn extract_proxy_dns_failures(line: &str) -> Option<(String, Option<String>)> {
    let marker = "connect error: dns resolve failed: couldn't find ip";
    let lower = line.to_lowercase();
    let pos = lower.find(marker)?;
    let target = line[..pos]
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .trim_matches(|c: char| ",;()".contains(c))
        .to_string();
    if target.is_empty() {
        return None;
    }
    let host = target
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(target.as_str())
        .trim_matches(|c: char| "[]".contains(c))
        .to_string();
    Some((target, if host.is_empty() { None } else { Some(host) }))
}

async fn get_service_health() -> Result<HealthResponse> {
    reqwest::ClientBuilder::new()
        .no_proxy()
        .build()?
        .get(format!("{SERVICE_URL}/health"))
        .send()
        .await?
        .json::<HealthResponse>()
        .await
        .context("failed to parse the clash-verge-service health response")
}

async fn get_service_clash_state() -> Result<JsonResponse> {
    reqwest::ClientBuilder::new()
        .no_proxy()
        .build()?
        .get(format!("{SERVICE_URL}/get_clash"))
        .send()
        .await?
        .json::<JsonResponse>()
        .await
        .context("failed to parse the clash-verge-service response")
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
    let running = installed && query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running;
    let health = get_service_health().await.ok();
    let api_ready = health.as_ref().map(|h| h.code == 0).unwrap_or(false);
    let clash = if api_ready { get_service_clash_state().await.ok() } else { None };
    let core_pid = clash.as_ref().and_then(|s| s.data.as_ref()).and_then(|d| d.pid);
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
        format!("service running, API ready, core managed by service (pid {}).", core_pid.unwrap())
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
        && get_service_health().await.map(|h| h.code == 0).unwrap_or(false) {
        return Ok(());
    }

    start_service_process()?;
    let timeout = Duration::from_secs(15);
    let started = std::time::Instant::now();

    loop {
        if query_service_state().unwrap_or(ServiceStateHint::Other) == ServiceStateHint::Running
            && get_service_health().await.map(|h| h.code == 0).unwrap_or(false) {
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

pub(super) async fn run_core_by_service(config_file: &PathBuf) -> Result<()> {
    ensure_service_ready().await?;
    let status = check_service().await?;
    if status.core_managed {
        stop_core_by_service().await?;
        sleep(Duration::from_secs(1)).await;
    }
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
    let mut map = HashMap::new();
    map.insert("core_type", clash_core.as_str());
    map.insert("bin_path", bin_path);
    map.insert("config_dir", config_dir);
    map.insert("config_file", config_file);
    map.insert("log_file", log_path);
    log::info!(target: "app", "service mode enabled: calling /start_clash");
    log::info!(target: "app", "start_clash request field summary: core_type={clash_core}, bin_path_exists={}, config_dir_exists={}, config_file={}, log_file={}", bin_path_buf.exists(), config_dir_buf.exists(), config_file, log_path);
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
                    let tun_stack = cfg.tun.as_ref().and_then(|t| t.stack.clone()).unwrap_or_default();
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
    Ok(())
}

pub async fn diagnose_tun_outbound() -> Result<TunDiagnosticReport> {
    let mut reasons = vec![];
    let status = check_service().await?;
    let service_core_managed = status.core_managed;
    if !service_core_managed {
        reasons.push("service core not managed".to_string());
    }

    let client = reqwest::ClientBuilder::new().no_proxy().build()?;
    let cfg_resp = client.get(EXTERNAL_CONTROLLER_URL).send().await;
    let core_api_ready = cfg_resp
        .as_ref()
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if !core_api_ready {
        reasons.push("core API not ready".to_string());
    }

    let mut tun_enabled = false;
    let mut dns_hijack_ok = false;
    let mut mode = None;
    let mut proxy_server_nameserver = vec![];
    let mut dns_nameserver = vec![];
    let mut dns_respect_rules = None;
    let mut dns_enhanced_mode = None;
    let mut dns_fake_ip_range = None;
    if let Ok(resp) = cfg_resp {
        if let Ok(v) = resp.json::<JsonValue>().await {
            mode = v.get("mode").and_then(|m| m.as_str()).map(|s| s.to_string());
            if let Some(tun) = v.get("tun") {
                tun_enabled = tun.get("enable").and_then(|b| b.as_bool()).unwrap_or(false);
                dns_hijack_ok = tun
                    .get("dns-hijack")
                    .and_then(|d| d.as_array())
                    .map(|arr| arr.iter().any(|x| x.as_str().unwrap_or("").contains(":53")))
                    .unwrap_or(false);
            }
            if let Some(dns) = v.get("dns") {
                proxy_server_nameserver = collect_string_array(dns.get("proxy-server-nameserver"));
                dns_nameserver = collect_string_array(dns.get("nameserver"));
                dns_respect_rules = dns.get("respect-rules").and_then(|x| x.as_bool());
                dns_enhanced_mode = dns.get("enhanced-mode").and_then(|x| x.as_str()).map(|x| x.to_string());
                dns_fake_ip_range = dns.get("fake-ip-range").and_then(|x| x.as_str()).map(|x| x.to_string());
            }
        }
    }
    if !tun_enabled { reasons.push("TUN not enabled".to_string()); }
    if tun_enabled && !dns_hijack_ok { reasons.push("DNS hijack not working".to_string()); }

    let route_output = StdCommand::new("route").args(["print", "0.0.0.0"]).output().ok();
    let route_text = route_output.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let route_injected = route_text.contains("198.18.0.2") || route_text.contains("198.18.0.1");
    if tun_enabled && !route_injected { reasons.push("route not injected".to_string()); }

    let netsh = StdCommand::new("netsh").args(["interface", "ipv4", "show", "interfaces"]).output().ok();
    let netsh_text = netsh.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default().to_lowercase();
    let mut adapter_candidates: Vec<String> = netsh_text
        .lines()
        .filter(|l| ["tun", "wintun", "clash", "meta", "mihomo"].iter().any(|k| l.contains(k)))
        .map(|s| s.trim().to_string())
        .collect();
    adapter_candidates.sort();
    adapter_candidates.dedup();
    let multiple_tun_adapters_detected = adapter_candidates.len() > 1;
    if multiple_tun_adapters_detected { reasons.push("multiple TUN adapters detected".to_string()); }

    let mut outbound_group = None;
    let mut selected_proxy = None;
    let mut selected_proxy_type = None;
    let mut selected_proxy_server_host = None;
    let mut selected_proxy_server_port = None;
    let mut selected_proxy_is_direct = false;
    let mut selected_proxy_delay = None;
    let mut selected_proxy_reachable = None;
    let mut selected_proxy_delay_error = None;
    if core_api_ready {
        if let Ok(resp) = client.get("http://127.0.0.1:9097/proxies").send().await {
            if let Ok(v) = resp.json::<JsonValue>().await {
                let proxies = v.get("proxies").cloned().unwrap_or(JsonValue::Null);
                for group_name in ["MATCH", "GLOBAL", "🚀 节点选择"] {
                    if let Some(now) = proxies.get(group_name).and_then(|g| g.get("now")).and_then(|n| n.as_str()) {
                        outbound_group = Some(group_name.to_string());
                        selected_proxy = Some(now.to_string());
                        break;
                    }
                }
                if let Some(proxy_name) = selected_proxy.as_deref() {
                    if let Some(node) = proxies.get(proxy_name) {
                        selected_proxy_type = node.get("type").and_then(|x| x.as_str()).map(|x| x.to_string());
                        selected_proxy_server_host = node.get("server").and_then(|x| x.as_str()).map(|x| x.to_string());
                        selected_proxy_server_port = node.get("port").and_then(|x| x.as_u64()).map(|x| x as u16);
                    }
                }
            }
        }
        selected_proxy_is_direct = selected_proxy_type
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("Direct"))
            .unwrap_or_else(|| selected_proxy.as_deref().map(|v| v.eq_ignore_ascii_case("DIRECT")).unwrap_or(false));
        if let Some(proxy) = selected_proxy.clone().filter(|_| !selected_proxy_is_direct) {
            let encoded_proxy = encode_url_path_segment(&proxy);
            let url = format!(
                "http://127.0.0.1:9097/proxies/{encoded_proxy}/delay?timeout=8000&url=https%3A%2F%2Fwww.google.com%2Fgenerate_204"
            );
            if let Ok(resp) = client.get(url).send().await {
                if let Ok(v) = resp.json::<JsonValue>().await {
                    selected_proxy_delay = v.get("delay").and_then(|d| d.as_i64());
                    selected_proxy_reachable = selected_proxy_delay.map(|d| d > 0 && d < 8000);
                    if selected_proxy_delay.is_none() {
                        selected_proxy_delay_error = v.get("error").and_then(|e| e.as_str()).map(|e| e.to_string()).or_else(|| Some(v.to_string()));
                    }
                }
            } else {
                selected_proxy_delay_error = Some("delay request failed".to_string());
            }
            if selected_proxy_reachable == Some(false) {
                reasons.push("TUN is enabled, but selected proxy is not reachable.".to_string());
            }
        } else if selected_proxy_is_direct {
            selected_proxy_delay_error = None;
            reasons.push("route selected DIRECT".to_string());
        }
    }

    let clash_state = get_service_clash_state().await.ok();
    let service_log_file = clash_state
        .as_ref()
        .and_then(|s| s.data.as_ref())
        .map(|d| d.log_file.clone());
    let mut service_log_summary = vec![];
    let mut proxy_dns_failed = false;
    let mut proxy_dns_failed_hosts: Vec<String> = vec![];
    let mut proxy_dns_failed_targets: Vec<String> = vec![];
    if let Some(path) = service_log_file.clone() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let keys = ["dial", "proxy", "timeout", "connect", "refused", "handshake", "route", "dns", "tun", "failed"];
            let lines: Vec<&str> = content.lines().rev().take(200).collect();
            for line in lines.into_iter().rev() {
                let l = line.to_lowercase();
                if keys.iter().any(|k| l.contains(k)) {
                    let sanitized = line.replace("token=", "token=***");
                    if let Some((target, host)) = extract_proxy_dns_failures(&sanitized) {
                        proxy_dns_failed = true;
                        proxy_dns_failed_targets.push(target);
                        if let Some(host) = host {
                            proxy_dns_failed_hosts.push(host);
                        }
                    }
                    service_log_summary.push(sanitized);
                }
            }
        }
    }

    if !selected_proxy_is_direct {
        if let Some(err) = selected_proxy_delay_error.as_deref() {
            if err.to_lowercase().contains("dns resolve failed") {
                proxy_dns_failed = true;
            }
        }
    }
    let proxy_server_host_is_domain = selected_proxy_server_host
        .as_deref()
        .map(is_probably_domain)
        .unwrap_or(false);
    let should_check_proxy_dns = proxy_server_host_is_domain && !selected_proxy_is_direct;
    if proxy_dns_failed && should_check_proxy_dns {
        if let Some(host) = selected_proxy_server_host.clone() {
            if !proxy_dns_failed_hosts.iter().any(|h| h == &host) {
                proxy_dns_failed_hosts.push(host);
            }
        }
    }
    proxy_dns_failed_hosts.sort();
    proxy_dns_failed_hosts.dedup();
    proxy_dns_failed_targets.sort();
    proxy_dns_failed_targets.dedup();

    let mut system_dns_resolved_hosts = vec![];
    if proxy_dns_failed && should_check_proxy_dns {
        for host in proxy_dns_failed_hosts.iter().take(3) {
            if let Ok(Ok(iter)) = timeout(Duration::from_secs(2), lookup_host((host.as_str(), 0))).await {
                let mut ips: Vec<String> = iter.map(|addr| addr.ip().to_string()).collect();
                ips.sort();
                ips.dedup();
                if !ips.is_empty() {
                    let fake_ip_flags = ips
                        .iter()
                        .map(|ip| is_likely_fake_ip(ip, dns_fake_ip_range.as_deref()))
                        .collect();
                    system_dns_resolved_hosts.push(SystemDnsResolvedHost { host: host.clone(), ips, fake_ip_flags });
                }
            }
        }
    }

    let system_dns_status = if !proxy_dns_failed || !should_check_proxy_dns {
        Some("not_tested".to_string())
    } else {
        Some(classify_system_dns_status(&system_dns_resolved_hosts))
    };

    let dns_proxy_server_nameserver_status = if !proxy_server_host_is_domain {
        Some("unknown".to_string())
    } else if tun_enabled
        && dns_hijack_ok
        && dns_enhanced_mode.as_deref() == Some("fake-ip")
        && proxy_server_nameserver
            == vec![
                "https://223.5.5.5/dns-query".to_string(),
                "https://223.6.6.6/dns-query".to_string(),
            ]
    {
        Some("runtime_injected".to_string())
    } else if proxy_server_nameserver.is_empty() {
        Some("implicit_fallback".to_string())
    } else {
        Some("configured".to_string())
    };

    let mut proxy_dns_failure_hint = None;
    proxy_dns_failed = proxy_dns_failed && should_check_proxy_dns;
    if proxy_dns_failed {
        reasons.push("selected proxy DNS failed".to_string());
        proxy_dns_failure_hint = Some(if system_dns_status.as_deref() == Some("fake-ip") {
            "系统 DNS 返回了 fake-ip，这通常来自 Mihomo fake-ip/TUN DNS hijack，不代表代理节点域名已解析到真实公网地址。代理节点域名应通过 proxy-server-nameserver 或 Mihomo 内部 DNS 解析。请检查 dns.proxy-server-nameserver、nameserver、fake-ip-filter、respect-rules 以及 DNS 出站路径。".to_string()
        } else if system_dns_status.as_deref() == Some("mixed") {
            "系统 DNS 返回了 fake-ip 与真实 IP 的混合结果。fake-ip 可能来自 Mihomo fake-ip/TUN DNS hijack，不能单独作为代理节点真实解析成功的依据。请优先检查 dns.proxy-server-nameserver、nameserver、fake-ip-filter、respect-rules 与 DNS 出站路径。".to_string()
        } else if system_dns_resolved_hosts.is_empty() {
            "当前选中代理节点的服务器域名在 Mihomo 内部解析失败，但这不一定代表域名本身失效。请检查 proxy-server-nameserver、respect-rules、DNS 出站路径或 TUN 回环。".to_string()
        } else {
            "系统 DNS 解析到了真实 IP，但 Mihomo 内部 DNS 对代理节点域名解析失败。请检查 dns.proxy-server-nameserver、nameserver、respect-rules 与 DNS 出站路径。".to_string()
        });
    } else if selected_proxy_is_direct {
        proxy_dns_failure_hint = Some("当前路由选择为 DIRECT；DIRECT 不是代理节点，因此跳过节点延迟测试和节点 DNS 诊断。".to_string());
    }

    if tun_enabled && dns_hijack_ok && route_injected && selected_proxy_reachable != Some(true) && !reasons.iter().any(|r| r.contains("selected proxy")) {
        reasons.push("outbound failed, check service log".to_string());
    }

    Ok(TunDiagnosticReport {
        tun_enabled,
        service_core_managed,
        core_api_ready,
        dns_hijack_ok,
        route_injected,
        multiple_tun_adapters_detected,
        adapter_candidates,
        mode,
        outbound_group,
        selected_proxy: selected_proxy.clone(),
        selected_proxy_type: selected_proxy_type.clone(),
        route_decision: selected_proxy,
        route_decision_type: selected_proxy_type,
        selected_proxy_server_host,
        selected_proxy_server_port,
        selected_proxy_is_direct,
        selected_proxy_delay,
        selected_proxy_reachable,
        selected_proxy_delay_error,
        proxy_dns_failed,
        proxy_dns_failed_hosts,
        proxy_dns_failed_targets,
        proxy_dns_failure_hint,
        system_dns_resolved_hosts,
        system_dns_status,
        dns_proxy_server_nameserver_status,
        dns_fake_ip_range,
        proxy_server_nameserver,
        dns_nameserver,
        dns_respect_rules,
        dns_enhanced_mode,
        service_log_file,
        service_log_summary,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::{classify_system_dns_status, is_ipv4_in_cidr, is_likely_fake_ip, SystemDnsResolvedHost};

    #[test]
    fn fake_ip_default_range_works() {
        assert!(is_likely_fake_ip("198.18.0.14", None));
        assert!(!is_likely_fake_ip("8.8.8.8", None));
    }

    #[test]
    fn fake_ip_uses_config_range() {
        assert!(is_likely_fake_ip("28.1.2.3", Some("28.0.0.1/8")));
    }

    #[test]
    fn fake_ip_invalid_config_falls_back_default_range() {
        assert!(is_likely_fake_ip("198.18.0.14", Some("not-a-cidr")));
    }

    #[test]
    fn cidr_match_works() {
        assert!(is_ipv4_in_cidr("198.18.10.1", "198.18.0.0/15"));
        assert!(!is_ipv4_in_cidr("198.20.10.1", "198.18.0.0/15"));
    }

    #[test]
    fn system_dns_status_fake_ip_only() {
        let hosts = vec![SystemDnsResolvedHost {
            host: "awjp.rocnet.vip".to_string(),
            ips: vec!["198.18.0.14".to_string()],
            fake_ip_flags: vec![true],
        }];
        assert_eq!(classify_system_dns_status(&hosts), "fake-ip");
    }

    #[test]
    fn system_dns_status_mixed() {
        let hosts = vec![SystemDnsResolvedHost {
            host: "awjp.rocnet.vip".to_string(),
            ips: vec!["198.18.0.14".to_string(), "1.1.1.1".to_string()],
            fake_ip_flags: vec![true, false],
        }];
        assert_eq!(classify_system_dns_status(&hosts), "mixed");
    }

    #[test]
    fn proxy_server_nameserver_empty_is_implicit_fallback() {
        let proxy_server_nameserver: Vec<String> = vec![];
        let is_domain = true;
        let status = if !is_domain {
            "unknown"
        } else if proxy_server_nameserver.is_empty() {
            "implicit_fallback"
        } else {
            "configured"
        };
        assert_eq!(status, "implicit_fallback");
    }
}

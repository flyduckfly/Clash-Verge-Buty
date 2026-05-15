/// diagnostic: diagnostics only; no core start/stop
#[cfg(target_os = "windows")]
use anyhow::Result;
#[cfg(target_os = "windows")]
use serde::Serialize;

#[cfg(target_os = "windows")]
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
    pub selected_node_group: Option<String>,
    pub proxy_group_now: Option<String>,
    pub outbound_group: Option<String>,
    pub selected_proxy: Option<String>,
    pub selected_proxy_type: Option<String>,
    pub route_decision: Option<String>,
    pub route_decision_type: Option<String>,
    pub route_chain: Vec<String>,
    pub route_decision_for_test_target: Option<String>,
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
    pub system_dns_resolved_hosts: Vec<super::win_service::SystemDnsResolvedHost>,
    pub system_dns_status: Option<String>,
    pub dns_proxy_server_nameserver_status: Option<String>,
    pub dns_fake_ip_range: Option<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub dns_nameserver: Vec<String>,
    pub dns_respect_rules: Option<bool>,
    pub dns_enhanced_mode: Option<String>,
    pub tcp_concurrent: Option<bool>,
    pub tcp_concurrent_warning: Option<String>,
    pub runtime_dns_source: Option<String>,
    pub final_config_path: Option<String>,
    pub config_read_error: Option<String>,
    pub service_log_file: Option<String>,
    pub service_log_summary: Vec<String>,
    pub reasons: Vec<String>,
}

#[cfg(target_os = "windows")]
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
    let mut tcp_concurrent = None;
    let mut dns_fake_ip_range = None;
    let (runtime_yaml, runtime_dns_source, final_config_path, config_read_error) =
        read_runtime_config_yaml();
    if let Some(yaml) = runtime_yaml.as_ref().and_then(|v| v.as_mapping()) {
        let dns = yaml.get("dns").and_then(|v| v.as_mapping());
        tcp_concurrent = yaml.get("tcp-concurrent").and_then(|v| v.as_bool());
        if let Some(dns) = dns {
            proxy_server_nameserver = dns
                .get("proxy-server-nameserver")
                .and_then(|v| v.as_sequence())
                .map(|s| {
                    s.iter()
                        .filter_map(|v| v.as_str())
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            dns_nameserver = dns
                .get("nameserver")
                .and_then(|v| v.as_sequence())
                .map(|s| {
                    s.iter()
                        .filter_map(|v| v.as_str())
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            dns_respect_rules = dns.get("respect-rules").and_then(|v| v.as_bool());
            dns_enhanced_mode = dns
                .get("enhanced-mode")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            dns_fake_ip_range = dns
                .get("fake-ip-range")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
        }
    }
    if let Ok(resp) = cfg_resp {
        if let Ok(v) = resp.json::<JsonValue>().await {
            mode = v
                .get("mode")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string());
            if let Some(tun) = v.get("tun") {
                tun_enabled = tun.get("enable").and_then(|b| b.as_bool()).unwrap_or(false);
                dns_hijack_ok = tun
                    .get("dns-hijack")
                    .and_then(|d| d.as_array())
                    .map(|arr| arr.iter().any(|x| x.as_str().unwrap_or("").contains(":53")))
                    .unwrap_or(false);
            }
            if proxy_server_nameserver.is_empty() {
                if let Some(dns) = v.get("dns") {
                    proxy_server_nameserver =
                        collect_string_array(dns.get("proxy-server-nameserver"));
                }
            }
        }
    }
    if !tun_enabled {
        reasons.push("TUN not enabled".to_string());
    }
    if tun_enabled && !dns_hijack_ok {
        reasons.push("DNS hijack not working".to_string());
    }

    let route_output = StdCommand::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok();
    let route_text = route_output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let route_injected = route_text.contains("198.18.0.2") || route_text.contains("198.18.0.1");
    if tun_enabled && !route_injected {
        reasons.push("route not injected".to_string());
    }

    let netsh = StdCommand::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok();
    let netsh_text = netsh
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
        .to_lowercase();
    let mut adapter_candidates: Vec<String> = netsh_text
        .lines()
        .filter(|l| {
            ["tun", "wintun", "clash", "meta", "mihomo"]
                .iter()
                .any(|k| l.contains(k))
        })
        .map(|s| s.trim().to_string())
        .collect();
    adapter_candidates.sort();
    adapter_candidates.dedup();
    let multiple_tun_adapters_detected = adapter_candidates.len() > 1;
    if multiple_tun_adapters_detected {
        reasons.push("multiple TUN adapters detected".to_string());
    }

    let mut outbound_group = None;
    let mut selected_node_group = None;
    let mut proxy_group_now = None;
    let mut selected_proxy = None;
    let mut selected_proxy_type = None;
    let mut selected_proxy_server_host = None;
    let mut selected_proxy_server_port = None;
    let mut selected_proxy_is_direct = false;
    let mut selected_proxy_delay = None;
    let mut selected_proxy_reachable = None;
    let mut selected_proxy_delay_error = None;
    let mut global_group_now: Option<String> = None;
    let mut route_chain: Vec<String> = vec![];
    let mut route_chain_loop = false;
    let mut route_decision_for_test_target: Option<String> = Some("unknown".to_string());
    if core_api_ready {
        if let Ok(resp) = client.get("http://127.0.0.1:9097/proxies").send().await {
            if let Ok(v) = resp.json::<JsonValue>().await {
                let proxies = v.get("proxies").cloned().unwrap_or(JsonValue::Null);
                let mut proxies_now_map: HashMap<String, String> = HashMap::new();
                if let Some(proxy_obj) = proxies.as_object() {
                    for (name, node) in proxy_obj {
                        if let Some(now) = node.get("now").and_then(|n| n.as_str()) {
                            proxies_now_map.insert(name.trim().to_string(), now.trim().to_string());
                        }
                    }
                }
                global_group_now = proxies_now_map.get("GLOBAL").cloned();
                if let Some(runtime_yaml) = runtime_yaml.as_ref() {
                    let groups = collect_group_names(runtime_yaml);
                    if let Some(match_outbound) = extract_match_outbound_from_rules(runtime_yaml) {
                        outbound_group = Some("MATCH".to_string());
                        selected_node_group = Some(match_outbound.clone());
                        let (resolved_chain, final_hop, looped) =
                            super::diagnostic::resolve_route_chain(
                                &match_outbound,
                                &groups,
                                &proxies_now_map,
                            );
                        route_chain.push("MATCH".to_string());
                        route_chain.extend(resolved_chain.clone());
                        route_chain_loop = looped;
                        route_decision_for_test_target =
                            final_hop.clone().or(Some("unknown".to_string()));
                        proxy_group_now = proxies_now_map.get(&match_outbound).cloned();
                        selected_proxy = final_hop.or_else(|| resolved_chain.last().cloned());
                    } else {
                        reasons
                            .push("unable to infer external route from runtime rules".to_string());
                    }
                } else {
                    reasons.push("unable to infer external route from runtime rules".to_string());
                }
                if let Some(proxy_name) = selected_proxy.as_deref() {
                    if let Some(node) = proxies.get(proxy_name) {
                        selected_proxy_type = node
                            .get("type")
                            .and_then(|x| x.as_str())
                            .map(|x| x.to_string());
                        selected_proxy_server_host = node
                            .get("server")
                            .and_then(|x| x.as_str())
                            .map(|x| x.to_string());
                        selected_proxy_server_port =
                            node.get("port").and_then(|x| x.as_u64()).map(|x| x as u16);
                    }
                }
            }
        }
        selected_proxy_is_direct = selected_proxy_type
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("Direct"))
            .unwrap_or_else(|| {
                selected_proxy
                    .as_deref()
                    .map(|v| v.eq_ignore_ascii_case("DIRECT"))
                    .unwrap_or(false)
            });
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
                        selected_proxy_delay_error = v
                            .get("error")
                            .and_then(|e| e.as_str())
                            .map(|e| e.to_string())
                            .or_else(|| Some(v.to_string()));
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
            let keys = [
                "dial",
                "proxy",
                "timeout",
                "connect",
                "refused",
                "handshake",
                "route",
                "dns",
                "tun",
                "failed",
            ];
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
            if let Ok(Ok(iter)) =
                timeout(Duration::from_secs(2), lookup_host((host.as_str(), 0))).await
            {
                let mut ips: Vec<String> = iter.map(|addr| addr.ip().to_string()).collect();
                ips.sort();
                ips.dedup();
                if !ips.is_empty() {
                    let fake_ip_flags = ips
                        .iter()
                        .map(|ip| {
                            super::diagnostic::is_likely_fake_ip(ip, dns_fake_ip_range.as_deref())
                        })
                        .collect();
                    system_dns_resolved_hosts.push(SystemDnsResolvedHost {
                        host: host.clone(),
                        ips,
                        fake_ip_flags,
                    });
                }
            }
        }
    }

    let system_dns_status = if !proxy_dns_failed || !should_check_proxy_dns {
        Some("not_tested".to_string())
    } else {
        Some(super::diagnostic::classify_system_dns_status(
            &system_dns_resolved_hosts,
        ))
    };

    let dns_proxy_server_nameserver_status = if config_read_error.is_some() {
        Some("unknown".to_string())
    } else if !proxy_server_host_is_domain {
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
        proxy_dns_failure_hint = Some(
            "当前路由选择为 DIRECT；DIRECT 不是代理节点，因此跳过节点延迟测试和节点 DNS 诊断。"
                .to_string(),
        );
    }

    if mode.as_deref() == Some("global")
        && global_group_now
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("DIRECT"))
            .unwrap_or(false)
    {
        reasons.push("global mode selected DIRECT".to_string());
    }
    if route_chain_loop {
        reasons.push("route_chain_loop".to_string());
    }
    if mode.as_deref() == Some("rule")
        && route_decision_for_test_target.as_deref() == Some("DIRECT")
    {
        reasons.push("rule mode external target routed to DIRECT".to_string());
    }
    if tun_enabled
        && dns_hijack_ok
        && route_injected
        && selected_proxy_reachable == Some(false)
        && !reasons.iter().any(|r| r.contains("selected proxy"))
    {
        reasons.push("outbound failed, check service log".to_string());
    }
    let (only_one_usage_storm, tcp_concurrent_warning) =
        super::diagnostic::tcp_concurrent_warning_from_logs(&service_log_summary, tcp_concurrent);
    if only_one_usage_storm && tcp_concurrent == Some(true) {
        reasons
            .push("tcp-concurrent may amplify socket exhaustion under outbound storm".to_string());
    }
    log::info!(target: "app", "diagnose network runtime: tun_enable={}, tcp_concurrent={:?}, only_one_usage_storm={}", tun_enabled, tcp_concurrent, only_one_usage_storm);

    Ok(TunDiagnosticReport {
        tun_enabled,
        service_core_managed,
        core_api_ready,
        dns_hijack_ok,
        route_injected,
        multiple_tun_adapters_detected,
        adapter_candidates,
        mode,
        selected_node_group,
        proxy_group_now,
        outbound_group,
        selected_proxy: selected_proxy.clone(),
        selected_proxy_type: selected_proxy_type.clone(),
        route_decision: selected_proxy.clone(),
        route_decision_type: selected_proxy_type,
        route_chain,
        route_decision_for_test_target,
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
        tcp_concurrent,
        tcp_concurrent_warning,
        runtime_dns_source: Some(runtime_dns_source),
        final_config_path,
        config_read_error,
        service_log_file,
        service_log_summary,
        reasons,
    })
}

#[cfg(target_os = "windows")]
pub fn resolve_route_chain(
    start: &str,
    group_names: &std::collections::HashSet<String>,
    proxies_now_map: &std::collections::HashMap<String, String>,
) -> (Vec<String>, Option<String>, bool) {
    let mut chain = vec![start.to_string()];
    let mut visited = std::collections::HashSet::new();
    let mut current = start.trim().to_string();
    loop {
        if !visited.insert(current.clone()) {
            return (chain, None, true);
        }
        if !group_names.contains(&current) {
            return (chain, Some(current), false);
        }
        let Some(next) = proxies_now_map.get(&current).cloned() else {
            return (chain, None, false);
        };
        chain.push(next.clone());
        current = next.trim().to_string();
    }
}

#[cfg(target_os = "windows")]
fn ipv4_to_u32(ip: std::net::Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

#[cfg(target_os = "windows")]
pub fn is_ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let (base, prefix_str) = match cidr.split_once('/') {
        Some(v) => v,
        None => return false,
    };
    let ip = match ip.parse::<std::net::Ipv4Addr>() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let base = match base.parse::<std::net::Ipv4Addr>() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let prefix: u32 = match prefix_str.parse::<u32>() {
        Ok(v) if v <= 32 => v,
        _ => return false,
    };
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (ipv4_to_u32(ip) & mask) == (ipv4_to_u32(base) & mask)
}

#[cfg(target_os = "windows")]
pub fn is_likely_fake_ip(ip: &str, config_fake_ip_range: Option<&str>) -> bool {
    if let Some(range) = config_fake_ip_range
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if is_ipv4_in_cidr(ip, range) {
            return true;
        }
    }
    is_ipv4_in_cidr(ip, "198.18.0.0/15")
}

#[cfg(target_os = "windows")]
pub fn classify_system_dns_status(
    system_dns_resolved_hosts: &[super::win_service::SystemDnsResolvedHost],
) -> String {
    if system_dns_resolved_hosts.is_empty() {
        return "failed".to_string();
    }
    let (mut has_fake, mut has_real) = (false, false);
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

#[cfg(target_os = "windows")]
pub fn tcp_concurrent_warning_from_logs(
    service_log_summary: &[String],
    tcp_concurrent: Option<bool>,
) -> (bool, Option<String>) {
    let only_one_usage_storm = service_log_summary
        .iter()
        .filter(|line| line.contains("Only one usage of each socket address"))
        .count()
        >= 5;
    let warning = if only_one_usage_storm && tcp_concurrent == Some(true) {
        Some("当前出口节点连接风暴，tcp-concurrent 可能放大本机端口耗尽。".to_string())
    } else {
        None
    };
    (only_one_usage_storm, warning)
}

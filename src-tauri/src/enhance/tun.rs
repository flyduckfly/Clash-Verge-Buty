use serde_yaml::{Mapping, Value};
use crate::core::handle::Handle;
const DEFAULT_PROXY_SERVER_NAMESERVER: [&str; 2] = [
    "https://223.5.5.5/dns-query",
    "https://223.6.6.6/dns-query",
];

macro_rules! revise {
    ($map: expr, $key: expr, $val: expr) => {
        let ret_key = Value::String($key.into());
        $map.insert(ret_key, Value::from($val));
    };
}

// if key not exists then append value
macro_rules! append {
    ($map: expr, $key: expr, $val: expr) => {
        let ret_key = Value::String($key.into());
        if !$map.contains_key(&ret_key) {
            $map.insert(ret_key, Value::from($val));
        }
    };
}

pub fn use_tun(
    mut config: Mapping,
    enable: bool,
    source_has_tun: bool,
    default_tun: Mapping,
) -> Mapping {
    let tun_key = Value::from("tun");
    let tun_val = config.get(&tun_key);
    let tun_existed = tun_val.is_some();
    log::info!(target: "app", "tun existed before sync: {tun_existed}, tun existed in source: {source_has_tun}, tun enabled by ui: {enable}");
    Handle::emit_log("info", format!("[tun] sync start: existed_before={tun_existed}, existed_in_source={source_has_tun}, enabled_by_ui={enable}"));

    if enable {
        let mut tun_val = tun_val
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_else(|| default_tun.clone());
        revise!(tun_val, "enable", true);
        revise!(config, "tun", tun_val);
        Handle::emit_log("info", "[tun] action: inject/update tun and set enable=true");
    } else if tun_existed || source_has_tun {
        let mut tun_val = tun_val
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_else(|| default_tun.clone());
        revise!(tun_val, "enable", false);
        revise!(config, "tun", tun_val);
        Handle::emit_log("info", "[tun] action: keep tun and set enable=false");
    } else {
        config.remove(&tun_key);
        Handle::emit_log("info", "[tun] action: leave tun absent");
        return config;
    }

    let stack = config
        .get("tun")
        .and_then(Value::as_mapping)
        .and_then(|m| m.get("stack"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Handle::emit_log("info", format!("[tun] stack={stack}"));

    if enable {
        use_dns_for_tun(config)
    } else {
        config
    }
}

fn use_dns_for_tun(mut config: Mapping) -> Mapping {
    let dns_key = Value::from("dns");
    let dns_val = config.get(&dns_key);

    let mut dns_val = dns_val.map_or(Mapping::new(), |val| {
        val.as_mapping().cloned().unwrap_or(Mapping::new())
    });

    // 开启tun将同时开启dns
    revise!(dns_val, "enable", true);

    append!(dns_val, "enhanced-mode", "fake-ip");
    append!(dns_val, "fake-ip-range", "198.18.0.1/16");
    append!(
        dns_val,
        "nameserver",
        vec!["114.114.114.114", "223.5.5.5", "8.8.8.8"]
    );
    append!(dns_val, "fallback", vec![] as Vec<&str>);

    inject_default_proxy_server_nameserver_if_needed(&mut config, &mut dns_val);

    #[cfg(target_os = "windows")]
    append!(
        dns_val,
        "fake-ip-filter",
        vec![
            "dns.msftncsi.com",
            "www.msftncsi.com",
            "www.msftconnecttest.com"
        ]
    );
    revise!(config, "dns", dns_val);
    config
}

fn inject_default_proxy_server_nameserver_if_needed(config: &mut Mapping, dns_val: &mut Mapping) {
    let tun_hijack_non_empty = config
        .get("tun")
        .and_then(Value::as_mapping)
        .and_then(|m| m.get("dns-hijack"))
        .and_then(Value::as_sequence)
        .map(|seq| !seq.is_empty())
        .unwrap_or(false);
    let enhanced_fake_ip = dns_val
        .get("enhanced-mode")
        .and_then(Value::as_str)
        .map(|s| s.eq_ignore_ascii_case("fake-ip"))
        .unwrap_or(false);
    if !(tun_hijack_non_empty && enhanced_fake_ip) {
        return;
    }

    let should_inject = dns_val
        .get("proxy-server-nameserver")
        .and_then(Value::as_sequence)
        .map(|seq| seq.is_empty())
        .unwrap_or(true);

    if should_inject {
        dns_val.insert(
            Value::from("proxy-server-nameserver"),
            Value::Sequence(
                DEFAULT_PROXY_SERVER_NAMESERVER
                    .iter()
                    .map(|s| Value::String((*s).to_string()))
                    .collect(),
            ),
        );
        log::info!(target: "app", "Injected default dns.proxy-server-nameserver for TUN + fake-ip + DNS hijack runtime config");
    } else {
        log::debug!(target: "app", "dns.proxy-server-nameserver already configured, skip injection");
    }
}

#[cfg(test)]
mod tests {
    use super::use_tun;
    use serde_yaml::{Mapping, Value};

    fn m() -> Mapping { Mapping::new() }
    fn build_config(tun_enable: bool, dns_hijack: Option<Vec<&str>>, enhanced_mode: Option<&str>, psn: Option<Value>) -> Mapping {
        let mut c = m();
        let mut tun = m();
        tun.insert(Value::from("enable"), Value::from(tun_enable));
        if let Some(h) = dns_hijack {
            tun.insert(Value::from("dns-hijack"), Value::Sequence(h.into_iter().map(Value::from).collect()));
        }
        c.insert(Value::from("tun"), Value::Mapping(tun));
        if enhanced_mode.is_some() || psn.is_some() {
            let mut dns = m();
            if let Some(mode) = enhanced_mode {
                dns.insert(Value::from("enhanced-mode"), Value::from(mode));
            }
            if let Some(v) = psn {
                dns.insert(Value::from("proxy-server-nameserver"), v);
            }
            c.insert(Value::from("dns"), Value::Mapping(dns));
        }
        c
    }

    #[test]
    fn inject_when_dns_missing() {
        let c = build_config(true, Some(vec!["any:53"]), Some("fake-ip"), None);
        let out = use_tun(c, true, true, m());
        let seq = out.get("dns").and_then(Value::as_mapping).and_then(|d| d.get("proxy-server-nameserver")).and_then(Value::as_sequence).unwrap();
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn keep_user_proxy_server_nameserver() {
        let c = build_config(true, Some(vec!["any:53"]), Some("fake-ip"), Some(Value::Sequence(vec![Value::from("https://user.dns/dns-query")])));
        let out = use_tun(c, true, true, m());
        let seq = out.get("dns").and_then(Value::as_mapping).and_then(|d| d.get("proxy-server-nameserver")).and_then(Value::as_sequence).unwrap();
        assert_eq!(seq.len(), 1);
    }

    #[test]
    fn inject_when_empty_array() {
        let c = build_config(true, Some(vec!["any:53"]), Some("fake-ip"), Some(Value::Sequence(vec![])));
        let out = use_tun(c, true, true, m());
        let seq = out.get("dns").and_then(Value::as_mapping).and_then(|d| d.get("proxy-server-nameserver")).and_then(Value::as_sequence).unwrap();
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn no_inject_when_tun_disabled() {
        let c = build_config(false, Some(vec!["any:53"]), Some("fake-ip"), None);
        let out = use_tun(c, false, true, m());
        let has = out.get("dns").and_then(Value::as_mapping).and_then(|d| d.get("proxy-server-nameserver")).is_some();
        assert!(!has);
    }

    #[test]
    fn no_inject_when_not_fake_ip_mode() {
        let c = build_config(true, Some(vec!["any:53"]), Some("redir-host"), None);
        let out = use_tun(c, true, true, m());
        let has = out.get("dns").and_then(Value::as_mapping).and_then(|d| d.get("proxy-server-nameserver")).is_some();
        assert!(!has);
    }

    #[test]
    fn no_inject_when_dns_hijack_empty() {
        let c = build_config(true, Some(vec![]), Some("fake-ip"), None);
        let out = use_tun(c, true, true, m());
        let has = out.get("dns").and_then(Value::as_mapping).and_then(|d| d.get("proxy-server-nameserver")).is_some();
        assert!(!has);
    }
}

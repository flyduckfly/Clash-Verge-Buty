mod chain;
pub mod field;
mod merge;
mod script;
mod tun;

use self::chain::*;
use self::field::*;
use self::merge::*;
use self::script::*;
use self::tun::*;
use crate::config::Config;
use serde_yaml::{Mapping, Value};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

type ResultLog = Vec<(String, String)>;

/// Enhance mode
/// 返回最终订阅、该订阅包含的键、和script执行的结果
pub fn enhance() -> (Mapping, Vec<String>, HashMap<String, ResultLog>) {
    // config.yaml 的订阅
    let clash_config = { Config::clash().latest().0.clone() };

    let (clash_core, enable_tun, enable_builtin) = {
        let verge = Config::verge();
        let verge = verge.latest();
        (
            verge.clash_core.clone(),
            verge.enable_tun_mode.unwrap_or(false),
            verge.enable_builtin_enhanced.unwrap_or(true),
        )
    };

    // 从profiles里拿东西
    let (mut config, chain) = {
        let profiles = Config::profiles();
        let profiles = profiles.latest();

        let current = profiles.current_mapping().unwrap_or_default();

        let chain = match profiles.chain.as_ref() {
            Some(chain) => chain
                .iter()
                .filter_map(|uid| profiles.get_item(uid).ok())
                .filter_map(<Option<ChainItem>>::from)
                .collect::<Vec<ChainItem>>(),
            None => vec![],
        };

        (current, chain)
    };

    let mut result_map = HashMap::new(); // 保存脚本日志
    let mut exists_keys = use_keys(&config); // 保存出现过的keys

    // 处理用户的profile
    chain.into_iter().for_each(|item| match item.data {
        ChainType::Merge(merge) => {
            exists_keys.extend(use_keys(&merge));
            config = use_merge(merge, config.to_owned());
        }
        ChainType::Script(script) => {
            let mut logs = vec![];

            match use_script(script, config.to_owned()) {
                Ok((res_config, res_logs)) => {
                    exists_keys.extend(use_keys(&res_config));
                    config = res_config;
                    logs.extend(res_logs);
                }
                Err(err) => logs.push(("exception".into(), err.to_string())),
            }

            result_map.insert(item.uid, logs);
        }
    });

    let source_has_tun = config.get("tun").is_some();
    let clash_tun_default = clash_config
        .get("tun")
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();

    // 合并默认的config（tun 由 use_tun 统一处理，避免来源混淆）
    for (key, value) in clash_config.into_iter() {
        if key.as_str() != Some("tun") {
            config.insert(key, value);
        }
    }

    // 内建脚本最后跑
    if enable_builtin {
        ChainItem::builtin()
            .into_iter()
            .filter(|(s, _)| s.is_support(clash_core.as_ref()))
            .map(|(_, c)| c)
            .for_each(|item| {
                log::debug!(target: "app", "run builtin script {}", item.uid);

                match item.data {
                    ChainType::Script(script) => match use_script(script, config.to_owned()) {
                        Ok((res_config, _)) => {
                            config = res_config;
                        }
                        Err(err) => {
                            log::error!(target: "app", "builtin script error `{err}`");
                        }
                    },
                    _ => {}
                }
            });
    }

    config = use_tun(config, enable_tun, source_has_tun, clash_tun_default);
    config = use_sort(config);
    config = apply_external_merge_rule(config);

    let mut exists_set = HashSet::new();
    exists_set.extend(exists_keys.into_iter());
    exists_keys = exists_set.into_iter().collect();

    (config, exists_keys, result_map)
}

fn external_merge_rule_path_from(exe_path: &Path) -> Option<PathBuf> {
    exe_path.parent().map(|dir| dir.join("merge-rule.yaml"))
}

fn external_merge_rule_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| external_merge_rule_path_from(&exe))
}

fn external_merge_rule_template() -> &'static str {
    "# Clash Verge Buty external merge override file\n# This file is loaded after the runtime config is generated.\n# Values here override the generated runtime config.\n#\n# Example for TUN troubleshooting:\n#\n# ipv6: false\n#\n# dns:\n#   ipv6: false\n#\n# tun:\n#   route-exclude-address:\n#     - 223.5.5.5/32\n#     - 223.6.6.6/32\n#\n# Optional: bind outbound traffic to a physical interface.\n# Do not enable this unless you know your interface name.\n#\n# interface-name: WLAN\n"
}

fn ensure_external_merge_rule_template_exists_at(path: &Path) {
    if path.exists() {
        return;
    }

    if let Err(err) = std::fs::write(path, external_merge_rule_template()) {
        log::warn!(target: "app", "Failed to create external merge-rule.yaml template ({}): {}", path.display(), err);
        return;
    }

    log::info!(target: "app", "Created external merge-rule.yaml template: {}", path.display());
}

pub fn ensure_external_merge_rule_template_exists() {
    let Some(path) = external_merge_rule_path() else {
        return;
    };

    ensure_external_merge_rule_template_exists_at(&path);
}

fn load_external_merge_rule(path: &Path) -> Option<Mapping> {
    if !path.exists() {
        return None;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            log::warn!(target: "app", "Failed to read external merge-rule.yaml ({}): {}", path.display(), err);
            return None;
        }
    };

    if content.trim().is_empty() {
        log::warn!(target: "app", "External merge-rule.yaml is empty: {}", path.display());
        return None;
    }

    match serde_yaml::from_str::<Value>(&content) {
        Ok(Value::Mapping(mapping)) => Some(mapping),
        Ok(_) => {
            log::warn!(target: "app", "External merge-rule.yaml root is not a mapping: {}", path.display());
            None
        }
        Err(err) => {
            log::warn!(target: "app", "Failed to parse external merge-rule.yaml ({}): {}", path.display(), err);
            None
        }
    }
}

fn deep_merge_mapping(mut base: Mapping, overlay: Mapping) -> Mapping {
    for (key, overlay_val) in overlay {
        let merged_val = match (base.remove(&key), overlay_val) {
            (Some(Value::Mapping(base_map)), Value::Mapping(overlay_map)) => {
                Value::Mapping(deep_merge_mapping(base_map, overlay_map))
            }
            (_, value) => value,
        };
        base.insert(key, merged_val);
    }
    base
}

fn apply_external_merge_rule(config: Mapping) -> Mapping {
    let Some(path) = external_merge_rule_path() else {
        return config;
    };
    let Some(merge_rule) = load_external_merge_rule(&path) else {
        return config;
    };

    let merged = deep_merge_mapping(config, merge_rule);
    log::info!(target: "app", "Applied external merge-rule.yaml: {}", path.display());
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn yaml_mapping(input: &str) -> Mapping {
        serde_yaml::from_str::<Mapping>(input).unwrap()
    }

    fn unique_temp_dir() -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cvb-merge-rule-test-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn deep_merge_nested_mapping_and_keep_existing_fields() {
        let base = yaml_mapping(
            r#"
dns:
  ipv6: true
  enhanced-mode: fake-ip
tun:
  enable: true
  dns-hijack:
    - any:53
"#,
        );
        let overlay = yaml_mapping(
            r#"
ipv6: false
dns:
  ipv6: false
tun:
  route-exclude-address:
    - 223.5.5.5/32
    - 223.6.6.6/32
"#,
        );

        let merged = deep_merge_mapping(base, overlay);
        assert_eq!(merged.get("ipv6").and_then(Value::as_bool), Some(false));
        assert_eq!(
            merged
                .get("dns")
                .and_then(Value::as_mapping)
                .and_then(|dns| dns.get("ipv6"))
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            merged
                .get("dns")
                .and_then(Value::as_mapping)
                .and_then(|dns| dns.get("enhanced-mode"))
                .and_then(Value::as_str),
            Some("fake-ip")
        );
        assert_eq!(
            merged
                .get("tun")
                .and_then(Value::as_mapping)
                .and_then(|tun| tun.get("enable"))
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn sequence_should_be_overridden() {
        let base = yaml_mapping("rules: [A, B]");
        let overlay = yaml_mapping("rules: [C]");
        let merged = deep_merge_mapping(base, overlay);
        let rules = merged.get("rules").and_then(Value::as_sequence).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].as_str(), Some("C"));
    }

    #[test]
    fn deep_merge_should_be_idempotent() {
        let base = yaml_mapping("dns:\n  enhanced-mode: fake-ip\nrules: [A, B]\n");
        let overlay = yaml_mapping("dns:\n  ipv6: false\nrules: [C]\n");
        let once = deep_merge_mapping(base.clone(), overlay.clone());
        let twice = deep_merge_mapping(once.clone(), overlay);
        assert_eq!(once, twice);
    }

    #[test]
    fn load_external_merge_rule_handles_missing_invalid_and_non_mapping() {
        let dir = unique_temp_dir();
        let path = dir.join("merge-rule.yaml");
        assert!(load_external_merge_rule(&path).is_none());

        std::fs::write(&path, ":\ninvalid").unwrap();
        assert!(load_external_merge_rule(&path).is_none());

        std::fs::write(&path, "- not\n- mapping").unwrap();
        assert!(load_external_merge_rule(&path).is_none());
    }

    #[test]
    fn load_external_merge_rule_valid_mapping() {
        let dir = unique_temp_dir();
        let path = dir.join("merge-rule.yaml");
        std::fs::write(&path, "ipv6: false\ndns:\n  ipv6: false\n").unwrap();
        let loaded = load_external_merge_rule(&path).unwrap();
        assert_eq!(loaded.get("ipv6").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn ensure_template_create_and_keep_existing_content() {
        let dir = unique_temp_dir();
        let path = dir.join("merge-rule.yaml");

        ensure_external_merge_rule_template_exists_at(&path);
        let created = std::fs::read_to_string(&path).unwrap();
        assert!(created.contains("# Clash Verge Buty external merge override file"));

        std::fs::write(&path, "ipv6: false\n").unwrap();
        ensure_external_merge_rule_template_exists_at(&path);
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert_eq!(persisted, "ipv6: false\n");
    }

    #[test]
    fn load_external_merge_rule_comment_only_should_skip() {
        let dir = unique_temp_dir();
        let path = dir.join("merge-rule.yaml");
        std::fs::write(&path, external_merge_rule_template()).unwrap();
        assert!(load_external_merge_rule(&path).is_none());
    }
    #[test]
    fn resolve_windows_portable_style_path_from_exe_parent() {
        let exe = PathBuf::from(r"C:\UserProgram\Clash.Verge.Buty.Portable\Clash-Verge-Buty.exe");
        let path = external_merge_rule_path_from(&exe).unwrap();
        assert_eq!(
            path,
            PathBuf::from(r"C:\UserProgram\Clash.Verge.Buty.Portable\merge-rule.yaml")
        );
    }
}

use crate::{config::Config, core::logger::Logger, utils::dirs};
use anyhow::Result;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

#[derive(Debug, Clone, Serialize)]
pub struct DebugRecordingStatus {
    pub recording: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugRecordingResult {
    pub path: Option<String>,
    pub started: bool,
    pub stopped: bool,
}

pub struct DebugRecorder {
    state: Arc<Mutex<DebugRecordingStatus>>,
}

impl DebugRecorder {
    pub fn global() -> &'static Self {
        static RECORDER: OnceCell<DebugRecorder> = OnceCell::new();
        RECORDER.get_or_init(|| DebugRecorder {
            state: Arc::new(Mutex::new(DebugRecordingStatus {
                recording: false,
                path: None,
            })),
        })
    }

    pub fn status(&self) -> DebugRecordingStatus {
        self.state.lock().clone()
    }

    pub fn start(&self) -> Result<DebugRecordingResult> {
        let mut state = self.state.lock();
        if state.recording {
            return Ok(DebugRecordingResult {
                path: state.path.clone(),
                started: false,
                stopped: false,
            });
        }
        let path = dirs::new_debug_log_file()?;
        Self::write_header(&path)?;
        state.recording = true;
        state.path = Some(path.to_string_lossy().to_string());
        let state_ref = self.state.clone();
        tauri::async_runtime::spawn(async move {
            let mut core_seen: usize = 0;
            let mut service_path: Option<PathBuf> = None;
            let mut service_offset: u64 = 0;
            loop {
                {
                    let s = state_ref.lock().clone();
                    if !s.recording {
                        break;
                    }
                    if let Some(path) = s.path {
                        let debug_path = PathBuf::from(path);
                        let _ = append_line(debug_path.clone(), "[snapshot] recorder alive");
                        let _ = collect_core_logs(debug_path.clone(), &mut core_seen);
                        let _ = collect_service_logs(
                            debug_path,
                            &mut service_path,
                            &mut service_offset,
                        );
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        Ok(DebugRecordingResult {
            path: state.path.clone(),
            started: true,
            stopped: false,
        })
    }

    pub fn stop(&self) -> DebugRecordingResult {
        let mut state = self.state.lock();
        if !state.recording {
            return DebugRecordingResult {
                path: state.path.clone(),
                started: false,
                stopped: false,
            };
        }
        let path = state.path.clone();
        state.recording = false;
        if let Some(p) = path.clone() {
            let _ = append_line(PathBuf::from(p), "[recorder] stopped");
        }
        DebugRecordingResult {
            path,
            started: false,
            stopped: true,
        }
    }

    fn write_header(path: &PathBuf) -> Result<()> {
        let verge = Config::verge().latest().clone();
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "# Clash Verge Debug Record")?;
        writeln!(f, "time={}", chrono::Local::now().to_rfc3339())?;
        writeln!(f, "app_version={}", env!("CARGO_PKG_VERSION"))?;
        writeln!(f, "mode={:?}", Config::runtime().latest().mode)?;
        writeln!(f, "tun_enable={}", verge.enable_tun_mode.unwrap_or(false))?;
        writeln!(
            f,
            "system_proxy_enable={}",
            verge.enable_system_proxy.unwrap_or(false)
        )?;
        Ok(())
    }
}

fn append_line(path: PathBuf, line: &str) -> Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{} {}", chrono::Local::now().format("%F %T"), line)?;
    Ok(())
}

fn collect_core_logs(debug_path: PathBuf, core_seen: &mut usize) -> Result<()> {
    let logs = Logger::global().get_log();
    let len = logs.len();
    let start = if *core_seen > len { 0 } else { *core_seen };
    for line in logs.iter().skip(start) {
        append_with_keyword(debug_path.clone(), "[core]", line)?;
    }
    *core_seen = len;
    Ok(())
}

fn collect_service_logs(
    debug_path: PathBuf,
    service_path: &mut Option<PathBuf>,
    service_offset: &mut u64,
) -> Result<()> {
    #[cfg(windows)]
    {
        let is_service = Config::verge()
            .latest()
            .enable_service_mode
            .unwrap_or(false);
        if !is_service {
            return Ok(());
        }
        let latest = dirs::get_latest_service_log_file()?;
        if let Some(latest) = latest {
            if service_path.as_ref() != Some(&latest) {
                *service_path = Some(latest.clone());
                *service_offset = 0;
                append_line(
                    debug_path.clone(),
                    &format!("[service] switched log file: {}", latest.to_string_lossy()),
                )?;
            }
            let meta = std::fs::metadata(&latest)?;
            if meta.len() < *service_offset {
                *service_offset = 0;
                append_line(
                    debug_path.clone(),
                    "[service] log file truncated; reset offset",
                )?;
            }
            let mut f = OpenOptions::new().read(true).open(&latest)?;
            f.seek(SeekFrom::Start(*service_offset))?;
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            *service_offset = f.stream_position()?;
            for line in buf.lines() {
                append_with_keyword(debug_path.clone(), "[service]", line)?;
            }
        }
    }
    Ok(())
}

fn append_with_keyword(debug_path: PathBuf, prefix: &str, line: &str) -> Result<()> {
    append_line(debug_path.clone(), &format!("{prefix} {line}"))?;
    const KEYS: [&str; 5] = [
        "reject loopback connection",
        "dns resolve failed",
        "Only one usage of each socket address",
        "context deadline exceeded",
        "handshake failed",
    ];
    if KEYS.iter().any(|k| line.contains(k)) {
        append_line(debug_path, &format!("[keyword-hit] {line}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debug_filename_format() {
        let p = dirs::new_debug_log_file().expect("path");
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("debug-"));
        assert!(name.ends_with(".log"));
    }
}

pub mod clash_api;
/// debug_recorder: debug file recording
pub mod debug_recorder;
/// diagnostic: diagnostics only; no core start/stop
pub mod diagnostic;
pub mod handle;
pub mod hotkey;
/// logger: UI log and log aggregation entry
pub mod logger;
/// manager: CoreManager lifecycle orchestration
pub mod manager;
/// sidecar: local core subprocess management
pub mod sidecar;
pub mod sysopt;
pub mod timer;
pub mod tray;
/// win_service: Windows service-hosted core and service API
pub mod win_service;
pub mod win_uwp;

pub use self::manager::*;

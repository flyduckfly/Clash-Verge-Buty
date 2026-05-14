use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::{collections::VecDeque, sync::Arc};

const LOGS_QUEUE_LEN: usize = 100;

pub struct Logger {
    log_data: Arc<Mutex<VecDeque<String>>>,
}

impl Logger {
    pub fn global() -> &'static Logger {
        static LOGGER: OnceCell<Logger> = OnceCell::new();

        LOGGER.get_or_init(|| Logger {
            log_data: Arc::new(Mutex::new(VecDeque::with_capacity(LOGS_QUEUE_LEN + 10))),
        })
    }

    pub fn get_log(&self) -> VecDeque<String> {
        self.log_data.lock().clone()
    }

    pub fn set_log(&self, text: String) {
        let mut logs = self.log_data.lock();
        if let Some(last) = logs.back_mut() {
            if *last == text {
                *last = format!("[x2] {text}");
                return;
            }
            if let Some((prefix, msg)) = last.split_once("] ") {
                if msg == text && prefix.starts_with("[x") && prefix.ends_with(']') {
                    let count = prefix
                        .trim_start_matches("[x")
                        .trim_end_matches(']')
                        .parse::<u64>()
                        .unwrap_or(1)
                        + 1;
                    *last = format!("[x{count}] {text}");
                    return;
                }
            }
        }
        if logs.len() > LOGS_QUEUE_LEN {
            logs.pop_front();
        }
        logs.push_back(text);
    }

    pub fn clear_log(&self) {
        let mut logs = self.log_data.lock();
        logs.clear();
    }
}

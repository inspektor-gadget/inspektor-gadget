extern "C" {
    fn gadgetLog(level: u32, msg: u64);
}

pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

fn string_to_buf_ptr(s: &str) -> u64 {
    let ptr = s.as_ptr() as u32;
    
    let len = s.len() as u32;
    
    (u64::from(len) << 32) | u64::from(ptr)
}

pub fn log_message(level: LogLevel, message: &str) {
    unsafe {
        gadgetLog(level as u32, string_to_buf_ptr(message));
    }
}
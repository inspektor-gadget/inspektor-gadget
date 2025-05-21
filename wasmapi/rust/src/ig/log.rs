// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::ig::helpers::string_to_buf_ptr; //relative paths may hinder in testing.

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "gadgetLog"]
    fn _log(level: u32, msg: u64);
}

pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

pub fn log(level: LogLevel, message: &str) {
    unsafe {
        _log(level as u32, string_to_buf_ptr(message));
    }
}

// Rust doesn't support default vardiac, but similar functionality are provided by macros allow for multiple arguments
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:expr),+ $(,)?) => {{
        let message = [$($arg),+].join(" ");
        $crate::ig::log::log($level, &message);
    }};
}

#[macro_export]
macro_rules! logf {
    ($level:expr, $fmt:literal $(, $arg:tt)* ) => {{
        let message = format!($fmt $(, $arg)*);
        $crate::ig::log::log($level, &message);
    }};
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log!($crate::ig::log::LogLevel::Error, $($arg)*);
    };
}

#[macro_export]
macro_rules! errorf {
    ($fmt:literal $(, $arg:tt)* ) => {
        $crate::logf!(LogLevel::Error, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log!(LogLevel::Warn, $($arg)*);
    };
}

#[macro_export]
macro_rules! warnf {
    ($fmt:literal $(, $arg:tt)* ) => {
        $crate::logf!(LogLevel::Warn, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log!(LogLevel::Info, $($arg)*);
    };
}

#[macro_export]
macro_rules! infof {
    ($fmt:literal $(, $arg:tt)* ) => {
        $crate::logf!(LogLevel::Info, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::log!(LogLevel::Debug, $($arg)*);
    };
}

#[macro_export]
macro_rules! debugf {
    ($fmt:literal $(, $arg:tt)* ) => {
        $crate::logf!(LogLevel::Debug, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::log!(LogLevel::Trace, $($arg)*);
    };
}

#[macro_export]
macro_rules! tracef {
    ($fmt:literal $(, $arg:tt)* ) => {
        $crate::logf!(LogLevel::Trace, $fmt $(, $arg)*);
    };
}

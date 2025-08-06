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

use crate::helpers::string_to_buf_ptr; //relative paths may hinder in testing.

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "gadgetLog"]
    fn _log(level: u32, msg: u64);

    #[link_name = "gadgetShouldLog"]
    fn _should_log(level: u32) -> u32;
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
        _log(level as u32, string_to_buf_ptr(message).0);
    }
}

pub fn should_log(level: LogLevel) -> bool {
    unsafe {
        _should_log(level as u32) == 1
    }
}

// Rust doesn't support variadic arguments, but macros allow for multiple arguments.
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:expr),+ $(,)?) => {{
        if $crate::log::should_log($level) {
            let message = [$($arg),+].join(" ");
            $crate::log::log($level, &message);
        }
    }};
}

#[macro_export]
macro_rules! logf {
    ($level:expr, $fmt:literal $(, $arg:tt)* ) => {{
        if $crate::log::should_log($level) {
            let message = format!($fmt $(, $arg)*);
            $crate::log::log($level, &message);
        }
    }};
}

#[macro_export]
macro_rules! error {
    ($($arg:expr)*) => {
        $crate::log!($crate::log::LogLevel::Error, $($arg)*);
    };
}

#[macro_export]
macro_rules! errorf {
    ($fmt:literal $(, $arg:expr)* ) => {
        $crate::logf!($crate::log::LogLevel::Error, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:expr)*) => {
        $crate::log!($crate::log::LogLevel::Warn, $($arg)*);
    };
}

#[macro_export]
macro_rules! warnf {
    ($fmt:literal $(, $arg:expr)* ) => {
        $crate::logf!($crate::log::LogLevel::Warn, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:expr)*) => {
        $crate::log!($crate::log::LogLevel::Info, $($arg)*);
    };
}

#[macro_export]
macro_rules! infof {
    ($fmt:literal $(, $arg:expr)* ) => {
        $crate::logf!($crate::log::LogLevel::Info, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:expr)*) => {
        $crate::log!($crate::log::LogLevel::Debug, $($arg)*);
    };
}

#[macro_export]
macro_rules! debugf {
    ($fmt:literal $(, $arg:expr)* ) => {
        $crate::logf!($crate::log::LogLevel::Debug, $fmt $(, $arg)*);
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:expr)*) => {
        $crate::log!($crate::log::LogLevel::Trace, $($arg)*);
    };
}

#[macro_export]
macro_rules! tracef {
    ($fmt:literal $(, $arg:expr)* ) => {
        $crate::logf!($crate::log::LogLevel::Trace, $fmt $(, $arg)*);
    };
}

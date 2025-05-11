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
use api::rust_bindings::{log::LogLevel,datasources::{DataSource, FieldKind, Field, Data}};
use std::sync::OnceLock;

static MODE_RAW_F: OnceLock<Field> = OnceLock::new();
static MODE_F: OnceLock<Field> = OnceLock::new();
static FLAGS_RAW_F: OnceLock<Field> = OnceLock::new();
static FLAGS_F: OnceLock<Field> = OnceLock::new();

static FLAG_NAMES: [&str; 13] = [
    "O_CREAT",
    "O_EXCL",
    "O_NOCTTY",
    "O_TRUNC",
    "O_APPEND",
    "O_NONBLOCK",
    "O_DSYNC",
    "O_FASYNC",
    "O_DIRECT",
    "O_LARGEFILE",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_NOATIME",
    // Note: O_CLOEXEC would be 1 << 19 (not covered if we're shifting by 6)
];

fn format_mode(mode: u16) -> String {
    let file_type = match mode & 0o170000 {
        0o040000 => 'd', // Directory
        0o100000 => '-', // Regular file
        0o120000 => 'l', // Symlink
        _ => '?',        // Unknown
    };

    let perms = [
        (mode & 0o400, 'r'),
        (mode & 0o200, 'w'),
        (mode & 0o100, 'x'),
        (mode & 0o040, 'r'),
        (mode & 0o020, 'w'),
        (mode & 0o010, 'x'),
        (mode & 0o004, 'r'),
        (mode & 0o002, 'w'),
        (mode & 0o001, 'x'),
    ];

    let mut result = String::with_capacity(10);
    result.push(file_type);
    for (bit, ch) in perms {
        result.push(if bit != 0 { ch } else { '-' });
    }
    result
}

fn data_callback(_source: DataSource, data: Data) {
    if let (Some(mode_raw_f), Some(mode_f)) = (MODE_RAW_F.get(), MODE_F.get()) {
        match mode_raw_f.get_data(data, FieldKind::Uint16) {
            Ok(mode_raw) => {
                if let Some(mode) = mode_raw.downcast_ref::<u16>(){
                    let _ = mode_f.set_data(data, &format_mode(*mode), FieldKind::String);
                }
            }
            Err(err) => {
                api::warnf!("failed to get mode: {:?}", err);
                return;
            }
        }
    }

    if let (Some(flags_raw_f), Some(flags_f)) = (FLAGS_RAW_F.get(), FLAGS_F.get()) {
        match flags_raw_f.get_data(data, FieldKind::Int32) {
            Ok(flags_raw) => {
                if let Some(flag) = flags_raw.downcast_ref::<i32>(){
                    let flags_str = decode_flags(*flag).join("|");
                    let _ = flags_f.set_data(data, &flags_str, FieldKind::String);
                }
            }
            Err(err) => {
                api::warnf!("failed to get flags: {:?}", err);
                return;
            }
        }
    }
}

fn decode_flags(mut flags: i32) -> Vec<&'static str> {
    let mut flags_str = Vec::new();

    // Access mode (lowest 2 bits)
    match flags & 0b11 {
        0 => flags_str.push("O_RDONLY"),
        1 => flags_str.push("O_WRONLY"),
        2 => flags_str.push("O_RDWR"),
        _ => {}
    }

    // Shift out access mode bits (6 bits as per comment in Go code)
    flags >>= 6;

    for (i, name) in FLAG_NAMES.iter().enumerate() {
        if (flags & (1 << i)) != 0 {
            flags_str.push(name);
        }
    }

    flags_str
}

#[no_mangle]
fn gadgetAPIVersion() -> u64 {
    1
}

#[no_mangle]
fn gadgetInit() -> i32 {
    let ds = match DataSource::get_datasource("open".to_string()) {
        Ok(ds) => ds,
        Err(err) => {
            api::errorf!("failed to get datasource: {:?}", err);
            return 1;
        }
    };

    let _mode_raw_f = match ds.get_field("mode_raw") {
        Ok(f) => {
            MODE_RAW_F.set(f).expect("Failed to set MODE_RAW_F");
            f
        },
        Err(err) => {
            api::errorf!("failed to get field: {:?}", err);
            return 1;
        }
    };

    let _mode_f = match ds.add_field("mode", FieldKind::String) {
        Ok(f) => {
            MODE_F.set(f).expect("Failed to set MODE_F");
            f},
        Err(err) => {
            api::errorf!("failed to add field: {:?}", err);
            return 1;
        }
    };

    let _flags_raw_f = match ds.get_field("flags_raw") {
        Ok(f) => {
            FLAGS_RAW_F.set(f).expect("Failed to set FLAGS_RAW_F");
            f},
        Err(err) => {
            api::errorf!("failed to get field: {:?}", err);
            return 1;
        }
    };

    let _flags_f = match ds.add_field("flags", FieldKind::String) {
        Ok(f) => {
            FLAGS_F.set(f).expect("Failed to set FLAGS_F");
            f},
        Err(err) => {
            api::errorf!("failed to add field: {:?}", err);
            return 1;
        }
    };

    match ds.subscribe_data(data_callback, 0){
        Ok(()) => api::info!("ds subscribed"),
        Err(err) => {
            api::errorf!("failed: {:?}", err);
            return 1;
        }
    };

    0
}


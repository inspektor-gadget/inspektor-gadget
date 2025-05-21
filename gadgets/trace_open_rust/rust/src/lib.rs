// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

use api::ig::{
    datasources::{Data, DataSource, FieldKind},
    fields::FieldKindData,
    log::LogLevel,
};
use file_mode::Mode;
static FLAG_NAMES: &[&str] = &[
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
    "O_CLOEXEC",
];

fn decode_flags(flags: i32) -> Vec<&'static str> {
    let mut flags_str = Vec::new();

    match flags & 0b11 {
        0 => flags_str.push("O_RDONLY"),
        1 => flags_str.push("O_WRONLY"),
        2 => flags_str.push("O_RDWR"),
        _ => {}
    }

    let shifted_flags = flags >> 6;
    for (i, &name) in FLAG_NAMES.iter().enumerate() {
        if (1 << i) & shifted_flags != 0 {
            flags_str.push(name);
        }
    }

    flags_str
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetAPIVersion() -> u64 {
    1
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let ds = match DataSource::get_datasource("open".to_string()) {
        Ok(ds) => ds,
        Err(e) => {
            api::errorf!("failed to get datasource: {:?}", e);
            return 1;
        }
    };

    let mode_raw_f = match ds.get_field("mode_raw") {
        Ok(f) => f,
        Err(e) => {
            api::errorf!("failed to get field: {:?}", e);
            return 1;
        }
    };

    let mode_f = match ds.add_field("mode", FieldKind::String) {
        Ok(f) => f,
        Err(e) => {
            api::errorf!("failed to add field: {:?}", e);
            return 1;
        }
    };

    let flags_raw_f = match ds.get_field("flags_raw") {
        Ok(f) => f,
        Err(e) => {
            api::errorf!("failed to get field: {:?}", e);
            return 1;
        }
    };

    let flags_f = match ds.add_field("flags", FieldKind::String) {
        Ok(f) => f,
        Err(e) => {
            api::errorf!("failed to add field: {:?}", e);
            return 1;
        }
    };

    match ds.subscribe_data(
        move |_source: DataSource, data: Data| {
            // mode
            match mode_raw_f.get_data(data, FieldKind::Uint16) {
                Ok(FieldKindData::Uint16(val)) => {
                    let mode = Mode::from(val as u32);
                    let mode_str = mode.to_string();
                    let _ = mode_f.set_data(data, &mode_str, FieldKind::String);
                }
                Ok(_) => api::warn!("mode_raw field is not a Uint16"),
                Err(e) => api::warnf!("failed to get mode: {}", e),
            }

            // flags
            match flags_raw_f.get_data(data, FieldKind::Int32) {
                Ok(FieldKindData::Int32(val)) => {
                    let decoded = decode_flags(val);
                    let flags_joined = decoded.join("|");
                    let _ = flags_f.set_data(data, &flags_joined, FieldKind::String);
                }
                Ok(_) => api::warn!("flags_raw field is not an Int32"),
                Err(e) => api::warnf!("failed to get flags: {}", e),
            }
        },
        0,
    ) {
        Ok(_) => {
            api::info!("subscribed to open");
        }
        Err(err) => {
            api::errorf!("failed: {:?}", err);
            return 1;
        }
    };

    0
}

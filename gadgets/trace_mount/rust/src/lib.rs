// Copyright 2025-2026 The Inspektor Gadget authors
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

use api::{
    datasources::{Data, DataSource, Field, FieldKind},
    fields::FieldData,
};

const OP_MOUNT: i32 = 0;
const OP_UMOUNT: i32 = 1;
const OP_FSOPEN: i32 = 2;
const OP_FSCONFIG: i32 = 3;
const OP_FSMOUNT: i32 = 4;
const OP_MOVE_MOUNT: i32 = 5;

const AT_FDCWD: i32 = -100;

// include/uapi/linux/mount.h
const FSOPEN_FLAGS: &[(u32, &str)] = &[(0x00000001, "FSOPEN_CLOEXEC")];

const FSMOUNT_FLAGS: &[(u32, &str)] = &[(0x00000001, "FSMOUNT_CLOEXEC")];

const FSCONFIG_CMDS: &[&str] = &[
    "FSCONFIG_SET_FLAG",
    "FSCONFIG_SET_STRING",
    "FSCONFIG_SET_BINARY",
    "FSCONFIG_SET_PATH",
    "FSCONFIG_SET_PATH_EMPTY",
    "FSCONFIG_SET_FD",
    "FSCONFIG_CMD_CREATE",
    "FSCONFIG_CMD_RECONFIGURE",
    "FSCONFIG_CMD_CREATE_EXCL",
];

const MOUNT_ATTR_FLAGS: &[(u32, &str)] = &[
    (0x00000001, "MOUNT_ATTR_RDONLY"),
    (0x00000002, "MOUNT_ATTR_NOSUID"),
    (0x00000004, "MOUNT_ATTR_NODEV"),
    (0x00000008, "MOUNT_ATTR_NOEXEC"),
    (0x00000010, "MOUNT_ATTR_NOATIME"),
    (0x00000020, "MOUNT_ATTR_STRICTATIME"),
    (0x00000080, "MOUNT_ATTR_NODIRATIME"),
    (0x00100000, "MOUNT_ATTR_IDMAP"),
    (0x00200000, "MOUNT_ATTR_NOSYMFOLLOW"),
];

const MOVE_MOUNT_FLAGS: &[(u32, &str)] = &[
    (0x00000001, "MOVE_MOUNT_F_SYMLINKS"),
    (0x00000002, "MOVE_MOUNT_F_AUTOMOUNTS"),
    (0x00000004, "MOVE_MOUNT_F_EMPTY_PATH"),
    (0x00000010, "MOVE_MOUNT_T_SYMLINKS"),
    (0x00000020, "MOVE_MOUNT_T_AUTOMOUNTS"),
    (0x00000040, "MOVE_MOUNT_T_EMPTY_PATH"),
    (0x00000100, "MOVE_MOUNT_SET_GROUP"),
    (0x00000200, "MOVE_MOUNT_BENEATH"),
];

/// Converts a bitmask to "A|B|0x..." using the given names; unknown bits are
/// printed in hex.
fn str_flags(flags: u32, names: &[(u32, &str)]) -> String {
    if flags == 0 {
        return "0x0".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut rest = flags;
    for (value, name) in names {
        if flags & value != 0 {
            parts.push(name.to_string());
            rest &= !value;
        }
    }
    if rest != 0 {
        parts.push(format!("{:#x}", rest));
    }
    parts.join("|")
}

fn str_fsconfig_cmd(cmd: u32) -> String {
    match FSCONFIG_CMDS.get(cmd as usize) {
        Some(name) => name.to_string(),
        None => format!("{}", cmd),
    }
}

fn str_fd(fd: i32) -> String {
    if fd == AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        fd.to_string()
    }
}

#[derive(Default)]
struct CallArgs {
    op: i32,
    src: String,
    dest: String,
    fs: String,
    flags: String,
    data: String,
    error_raw: u32,
    fd: i32,
    to_fd: i32,
    cmd: u32,
    aux: i32,
    fsflags: u32,
    attr_flags: u32,
    key: String,
    value: String,
}

fn get_call_str(a: &CallArgs) -> String {
    match a.op {
        OP_MOUNT => format!(
            r#"mount("{}", "{}", "{}", {}, "{}") = {}"#,
            a.src, a.dest, a.fs, a.flags, a.data, a.error_raw
        ),
        OP_UMOUNT => format!(r#"umount("{}", "{}") = {}"#, a.dest, a.flags, a.error_raw),
        OP_FSOPEN => format!(
            r#"fsopen("{}", {}) = {}"#,
            a.fs,
            str_flags(a.fsflags, FSOPEN_FLAGS),
            a.error_raw
        ),
        OP_FSCONFIG => format!(
            r#"fsconfig({}, {}, "{}", "{}", {}) = {}"#,
            a.fd,
            str_fsconfig_cmd(a.cmd),
            a.key,
            a.value,
            a.aux,
            a.error_raw
        ),
        OP_FSMOUNT => format!(
            r#"fsmount({}, {}, {}) = {}"#,
            a.fd,
            str_flags(a.fsflags, FSMOUNT_FLAGS),
            str_flags(a.attr_flags, MOUNT_ATTR_FLAGS),
            a.error_raw
        ),
        OP_MOVE_MOUNT => format!(
            r#"move_mount({}, "{}", {}, "{}", {}) = {}"#,
            str_fd(a.fd),
            a.src,
            str_fd(a.to_fd),
            a.dest,
            str_flags(a.fsflags, MOVE_MOUNT_FLAGS),
            a.error_raw
        ),
        _ => "".to_string(),
    }
}

fn get_field(ds: &DataSource, name: &str) -> Option<Field> {
    match ds.get_field(name) {
        Ok(f) => Some(f),
        Err(e) => {
            api::errorf!("failed to get field {}: {:?}", name, e);
            None
        }
    }
}

fn get_string(field: &Field, data: Data, max_size: u32) -> String {
    field.string(data, max_size).unwrap_or_default()
}

fn get_i32(field: &Field, data: Data) -> i32 {
    match field.get_data(data, FieldKind::Int32) {
        Ok(FieldData::Int32(v)) => v,
        _ => 0,
    }
}

fn get_u32(field: &Field, data: Data) -> u32 {
    match field.get_data(data, FieldKind::Uint32) {
        Ok(FieldData::Uint32(v)) => v,
        _ => 0,
    }
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let ds = match DataSource::get_datasource("mount".to_string()) {
        Ok(ds) => ds,
        Err(e) => {
            api::errorf!("failed to get datasource: {:?}", e);
            return 1;
        }
    };

    macro_rules! field {
        ($name:expr) => {
            match get_field(&ds, $name) {
                Some(f) => f,
                None => return 1,
            }
        };
    }

    let op_raw_field = field!("op_raw");
    let src_field = field!("src");
    let dest_field = field!("dest");
    let fs_field = field!("fs");
    let data_field = field!("data");
    let error_raw_field = field!("error_raw");
    let flags_field = field!("flags");
    let fd_field = field!("fd");
    let to_fd_field = field!("to_fd");
    let cmd_field = field!("cmd");
    let aux_field = field!("aux");
    let fsflags_field = field!("fsflags");
    let attr_flags_field = field!("attr_flags");
    let key_field = field!("key");
    let value_field = field!("value");

    let call_field = match ds.add_field("call", FieldKind::String) {
        Ok(f) => f,
        Err(e) => {
            api::errorf!("failed to add field: {:?}", e);
            return 1;
        }
    };

    let err = ds.subscribe(
        move |_source: DataSource, data: Data| {
            let args = CallArgs {
                op: get_i32(&op_raw_field, data),
                src: get_string(&src_field, data, 4096),
                dest: get_string(&dest_field, data, 4096),
                fs: get_string(&fs_field, data, 4096),
                flags: get_string(&flags_field, data, 512),
                data: get_string(&data_field, data, 512),
                error_raw: get_u32(&error_raw_field, data),
                fd: get_i32(&fd_field, data),
                to_fd: get_i32(&to_fd_field, data),
                cmd: get_u32(&cmd_field, data),
                aux: get_i32(&aux_field, data),
                fsflags: get_u32(&fsflags_field, data),
                attr_flags: get_u32(&attr_flags_field, data),
                key: get_string(&key_field, data, 512),
                value: get_string(&value_field, data, 512),
            };

            let _ = call_field.set_data(data, &get_call_str(&args));
        },
        9999,
    );

    if let Err(err) = &err {
        api::errorf!("subscribing to datasource: {:?}", err);
        return 1;
    }

    0
}

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

use api;

// We need to copy some declarations from the API to have access to the low
// level details.

#[repr(u32)] // Specifies the enums to be casted as u32, similar to C enums.
#[derive(Clone, Copy)]
enum SubscriptionType {
    _Invalid = 0,
    Data = 1,
    Array = 2,
    Packet = 3,
}

// Invalid string: Too big (17 MB, we only provide 16MB to WASM programs)
const INVALID_STR_PTR: u64 = 1024 * 1024 * 17 << 32;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct SyscallParamRaw {
    name: [u8; 32],
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct SyscallDeclarationRaw {
    name: [u8; 32],
    nr_params: u8,
    _padding: [u8; 3],
    params: [SyscallParamRaw; 6],
}

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "gadgetLog"]
    fn _log(level: u32, msg: u64);

    #[link_name = "newDataSource"]
    fn _new_datasource(name: u64, typ: u32) -> u32;

    #[link_name = "getDataSource"]
    fn _get_datasource(name: u64) -> u32;

    #[link_name = "dataSourceSubscribe"]
    fn _datasource_subscribe(ds: u32, typ: u32, prio: u32, cb: u64) -> u32;

    #[link_name = "dataSourceGetField"]
    fn _datasource_get_field(ds: u32, name: u64) -> u32;

    #[link_name = "dataSourceAddField"]
    fn _datasource_add_field(ds: u32, name: u64, kind: u32) -> u32;

    #[link_name = "dataSourceNewPacketSingle"]
    fn _datasource_new_packet_single(ds: u32) -> u32;

    #[link_name = "dataSourceNewPacketArray"]
    fn _datasource_new_packet_array(ds: u32) -> u32;

    #[link_name = "dataSourceEmitAndRelease"]
    fn _datasource_emit_and_release(ds: u32, packet: u32) -> u32;

    #[link_name = "dataSourceRelease"]
    fn _datasource_release(ds: u32, packet: u32) -> u32;

    #[link_name = "dataSourceUnreference"]
    fn _datasource_unreference(ds: u32) -> u32;

    #[link_name = "dataSourceIsReferenced"]
    fn _datasource_is_referenced(ds: u32) -> u32;

    #[link_name = "dataArrayNew"]
    fn _dataarray_new(d: u32) -> u32;

    #[link_name = "dataArrayAppend"]
    fn _dataarray_append(d: u32, data: u32) -> u32;

    #[link_name = "dataArrayRelease"]
    fn _dataarray_release(d: u32, data: u32) -> u32;

    #[link_name = "dataArrayLen"]
    fn _dataarray_len(d: u32) -> u32;

    #[link_name = "dataArrayGet"]
    fn _dataarray_get(d: u32, index: u32) -> u32;

    #[link_name = "fieldGetScalar"]
    fn _field_get_scalar(field: u32, data: u32, kind: u32, err_ptr: u32) -> u64;

    #[link_name = "fieldGetBuffer"]
    fn _field_get_buffer(field: u32, data: u32, kind: u32, dst: u64) -> i32;

    #[link_name = "fieldSet"]
    fn _field_set(field: u32, data: u32, kind: u32, value: u64) -> u32;

    #[link_name = "fieldAddTag"]
    fn _field_add_tag(field: u32, tag: u64) -> u32;

    #[link_name = "getParamValue"]
    fn _get_param_value(key: u64, dst: u64) -> u32;

    #[link_name = "setConfig"]
    fn _set_config(key: u64, val: u64, kind: u32) -> u32;

    #[link_name = "newMap"]
    fn _map_new(name: u64, typ: u32, key_size: u32, value_size: u32, max_entries: u32) -> u32;

    #[link_name = "getMap"]
    fn _map_get(name: u64) -> u32;

    #[link_name = "mapLookup"]
    fn _map_lookup(map: u32, key_ptr: u64, value_ptr: u64) -> u32;

    #[link_name = "mapUpdate"]
    fn _map_update(map: u32, key_ptr: u64, value_ptr: u64, flags: u64) -> u32;

    #[link_name = "mapDelete"]
    fn _map_delete(map: u32, key_ptr: u64) -> u32;

    #[link_name = "mapRelease"]
    fn _map_release(map: u32) -> u32;

    #[link_name = "getSyscallDeclaration"]
    fn _declaration(name: u64, pointer: u64) -> u32;

    #[link_name = "kallsymsSymbolExists"]
    fn _kallsyms_symbol_exists(symbol: u64) -> u32;
}

fn string_to_buf_ptr(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    let ptr = s.as_ptr() as u32;

    let len = s.len() as u32;

    (u64::from(len) << 32) | u64::from(ptr)
}

pub fn any_to_buf_ptr<T>(val: &T) -> Result<u64, String> {
    let size = std::mem::size_of_val(val);
    if size == 0 {
        return Err(String::from("zero-sized types not supported"));
    }
    let ptr = val as *const T as *const u8;
    let bytes = unsafe { std::slice::from_raw_parts(ptr, size) };

    let buf_ptr = bytes_to_buf_ptr(bytes);

    Ok(buf_ptr)
}

fn bytes_to_buf_ptr(b: &[u8]) -> u64 {
    let len = b.len() as u64;
    let ptr = b.as_ptr() as u64;
    (len << 32) | ptr
}

fn log_and_panic(msg: String) {
    unsafe {
        _log(api::log::LogLevel::Error as u32, string_to_buf_ptr(&msg));
    };
    panic!("{}", msg)
}

fn assert_zero<T: std::cmp::PartialEq<u32> + std::fmt::Display>(v: T, msg: &str)
{
    if v != 0 {
        log_and_panic(format!("{} is not zero: {}", v, msg));
    }
}

fn assert_non_zero<T: std::cmp::PartialEq<u32> + std::fmt::Display>(v: T, msg: &str)
{
    if v == 0 {
        log_and_panic(format!("{} is not zero: {}", v, msg));
    }
}

fn assert_equal<T: std::cmp::PartialEq + std::fmt::Display>(v0: T, v1: T, msg: &str)
{
    if v0 != v1 {
        log_and_panic(format!("{} != {}: {}", v0, v1, msg));
    }
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let ds_single_name = "myarrayds";
    let ds_array_name = "myarrayds";
    let field_name = "myfield";

    // Create some resources for testing at the very beginning
    let ds_single_handle = unsafe { _new_datasource(string_to_buf_ptr(ds_single_name), api::datasources::DataSourceType::Single as u32 as u32) };
    assert_non_zero(ds_single_handle, "_new_datasource: creating new single");

    let ds_array_handle = unsafe { _new_datasource(string_to_buf_ptr(ds_array_name), api::datasources::DataSourceType::Array as u32 as u32) };
    assert_non_zero(ds_single_handle, "_new_datasource: creating new array");

    let field_handle = unsafe { _datasource_add_field(ds_single_handle, string_to_buf_ptr(field_name), api::datasources::FieldKind::Uint32 as u32) };
    assert_non_zero(field_handle, "_datasource_add_field: creating new");

    /********** Log **********/
    unsafe {
        _log(api::log::LogLevel::Error as u32, INVALID_STR_PTR);
        _log(42, string_to_buf_ptr("hello-world")); // invalid log level
        _log(api::log::LogLevel::Error as u32, string_to_buf_ptr("")); // empty string
    };

    /********** DataSource **********/
    assert_zero(unsafe { _new_datasource(INVALID_STR_PTR, api::datasources::DataSourceType::Single as u32) }, "newDataSource: invalid name ptr");
    assert_zero(unsafe { _new_datasource(string_to_buf_ptr("foo"), 42) }, "newDataSource: invalid type");

    assert_non_zero(unsafe { _get_datasource(string_to_buf_ptr(ds_single_name)) }, "_get_datasource: existing");
    assert_zero(unsafe { _get_datasource(string_to_buf_ptr("foo")) }, "_get_datasource: non existing");
    assert_zero(unsafe { _get_datasource(INVALID_STR_PTR) }, "_get_datasource: invalid name ptr");

    assert_zero(unsafe { _datasource_subscribe(ds_single_handle, SubscriptionType::Data as u32, 0, 0) }, "_datasource_subscribe: single");
    assert_zero(unsafe { _datasource_subscribe(ds_single_handle, SubscriptionType::Packet as u32, 0, 0) }, "_datasource_subscribe: single + packet");
    assert_zero(unsafe { _datasource_subscribe(ds_array_handle, SubscriptionType::Array as u32, 0, 0) }, "_datasource_subscribe: array");
    assert_zero(unsafe { _datasource_subscribe(ds_array_handle, SubscriptionType::Packet as u32, 0, 0) }, "_datasource_subscribe: array + packet");
    assert_zero(unsafe { _datasource_subscribe(ds_array_handle, SubscriptionType::Data as u32, 0, 0) }, "_datasource_subscribe: array + single");
    assert_non_zero(unsafe { _datasource_subscribe(42, SubscriptionType::Data as u32, 0, 0) }, "_datasource_subscribe: bad handle");
    assert_non_zero(unsafe { _datasource_subscribe(field_handle, SubscriptionType::Data as u32, 0, 0) }, "_datasource_subscribe: bad handle type");
    assert_non_zero(unsafe { _datasource_subscribe(ds_single_handle, SubscriptionType::Array as u32, 0, 0) }, "_datasource_subscribe: bad handle type (single)");
    assert_non_zero(unsafe { _datasource_subscribe(ds_single_handle, 1005, 0, 0) }, "_datasource_subscribe: bad subscription type");

    assert_zero(unsafe { _datasource_add_field(ds_single_handle, string_to_buf_ptr(field_name), api::datasources::FieldKind::Uint32 as u32) }, "_datasource_add_field: duplicated");
    assert_zero(unsafe { _datasource_add_field(42, string_to_buf_ptr("foo"), api::datasources::FieldKind::Uint32 as u32) }, "_datasource_add_field: bad handle");
    assert_zero(unsafe { _datasource_add_field(field_handle, string_to_buf_ptr("foo"), api::datasources::FieldKind::Uint32 as u32) }, "_datasource_add_field: bad handle type");
    assert_zero(unsafe { _datasource_add_field(ds_single_handle, string_to_buf_ptr("foo"), 1005) }, "_datasource_add_field: bad kind");

    assert_non_zero(unsafe { _datasource_get_field(ds_single_handle, string_to_buf_ptr(field_name)) }, "_datasource_get_field: existing");
    assert_zero(unsafe { _datasource_get_field(42, string_to_buf_ptr("foo")) }, "_datasource_get_field: non existing");
    assert_zero(unsafe { _datasource_get_field(ds_single_handle, INVALID_STR_PTR) }, "_datasource_get_field: invalid name ptr");

    let packet_single_handle = unsafe { _datasource_new_packet_single(ds_single_handle) };
    assert_non_zero(packet_single_handle, "_datasource_new_packet_single: creating new");
    assert_zero(unsafe { _datasource_new_packet_single(42) }, "_datasource_new_packet_single: bad handle");
    assert_zero(unsafe { _datasource_new_packet_single(field_handle) }, "_datasource_new_packet_single: bad handle type");
    assert_zero(unsafe { _datasource_new_packet_single(ds_array_handle) }, "_datasource_new_packet_single: bad datasource type");

    let packet_array_handle = unsafe { _datasource_new_packet_array(ds_array_handle) };
    assert_non_zero(packet_array_handle, "_datasource_new_packet_array: creating new");
    assert_zero(unsafe { _datasource_new_packet_array(42) }, "_datasource_new_packet_array: bad handle");
    assert_zero(unsafe { _datasource_new_packet_array(field_handle) }, "_datasource_new_packet_array: bad handle type");
    assert_zero(unsafe { _datasource_new_packet_array(ds_single_handle) }, "_datasource_new_packet_array: bad datasource type");

    assert_non_zero(unsafe { _datasource_emit_and_release(42, packet_single_handle) }, "_datasource_emit_and_release: bad handle");
    assert_non_zero(unsafe { _datasource_emit_and_release(field_handle, packet_single_handle) }, "_datasource_emit_and_release: bad datasource handle type");
    assert_non_zero(unsafe { _datasource_emit_and_release(ds_single_handle, 42) }, "_datasource_emit_and_release: bad packet handle");
    assert_non_zero(unsafe { _datasource_emit_and_release(ds_single_handle, field_handle) }, "_datasource_emit_and_release: bad packet handle type ");

    assert_zero(unsafe { _datasource_release(ds_single_handle, packet_single_handle) }, "_datasource_release: ok");
    assert_non_zero(unsafe { _datasource_release(ds_single_handle, packet_single_handle) }, "_datasource_release: double release");
    assert_non_zero(unsafe { _datasource_release(42, packet_single_handle) }, "_datasource_release: bad handle");
    assert_non_zero(unsafe { _datasource_release(field_handle, packet_single_handle) }, "_datasource_release: bad handle type");
    assert_non_zero(unsafe { _datasource_release(ds_single_handle, 42) }, "_datasource_release: bad packet handle");
    assert_non_zero(unsafe { _datasource_release(ds_single_handle, field_handle) }, "_datasource_release: bad packet handle type");

    let data_elem_handle = unsafe { _dataarray_new(packet_array_handle) };
    assert_non_zero(data_elem_handle, "_dataarray_new: creating new");
    assert_zero(unsafe { _dataarray_new(42) }, "_dataarray_new: bad handle");
    assert_zero(unsafe { _dataarray_new(field_handle) }, "_dataarray_new: bad handle type");

    assert_zero(unsafe { _dataarray_append(packet_array_handle, data_elem_handle) }, "_dataarray_append: ok");
    assert_non_zero(unsafe { _dataarray_release(packet_array_handle, data_elem_handle) }, "_dataarray_release: bad data handle after append");
    assert_non_zero(unsafe { _dataarray_append(packet_array_handle, 42) }, "_dataarray_append: bad data handle");
    assert_non_zero(unsafe { _dataarray_append(packet_array_handle, field_handle) }, "_dataarray_append: bad data handle type");
    assert_non_zero(unsafe { _dataarray_append(42, data_elem_handle) }, "_dataarray_append: bad handle");
    assert_non_zero(unsafe { _dataarray_append(field_handle, data_elem_handle) }, "_dataarray_append: bad array handle type");

    assert_equal(unsafe { _dataarray_len(packet_array_handle) }, 1, "_dataarray_len");
    assert_zero(unsafe { _dataarray_len(42) }, "_dataarray_len: bad handle");
    assert_zero(unsafe { _dataarray_len(packet_single_handle) }, "_dataarray_len: bad handle type");

    let data_elem_handle2 = unsafe { _dataarray_new(packet_array_handle) };
    assert_zero(unsafe { _dataarray_release(packet_array_handle, data_elem_handle2) }, "_dataarray_release: ok");
    assert_non_zero(unsafe { _dataarray_release(packet_array_handle, data_elem_handle2) }, "_dataarray_release: double release");
    assert_non_zero(unsafe { _dataarray_release(packet_array_handle, 42) }, "_dataarray_release: bad data handle");
    assert_non_zero(unsafe { _dataarray_release(packet_array_handle, field_handle) }, "_dataarray_release: bad data handle type");
    assert_non_zero(unsafe { _dataarray_release(42, data_elem_handle2) }, "_dataarray_release: bad array handle");
    assert_non_zero(unsafe { _dataarray_release(field_handle, data_elem_handle2) }, "_dataarray_release: bad array handle type");

    assert_non_zero(unsafe { _dataarray_get(packet_array_handle, 0) }, "_dataarray_get: index 0");
    assert_zero(unsafe { _dataarray_get(packet_array_handle, 1) }, "_dataarray_get: index 1");
    assert_zero(unsafe { _dataarray_get(42, 0) }, "_dataarray_get: bad handle");
    assert_zero(unsafe { _dataarray_get(packet_single_handle, 0) }, "_dataarray_get: bad handle type");

    /* Fields */
    let data_handle = unsafe { _datasource_new_packet_single(ds_single_handle) };
    assert_non_zero(data_handle, "dataSourceNewPacketSingle: creating new");

    assert_zero(unsafe { _field_set(field_handle, data_handle, api::datasources::FieldKind::Uint32 as u32, 1234) }, "_field_set: ok");
    assert_non_zero(unsafe { _field_set(field_handle, data_handle, api::datasources::FieldKind::Uint64 as u32, 1234) }, "_field_set: bad kind");
    assert_non_zero(unsafe { _field_set(field_handle, data_handle, 1005, 1234) }, "_field_set: bad kind");
    assert_non_zero(unsafe { _field_set(field_handle, field_handle, api::datasources::FieldKind::Uint32 as u32, 1234) }, "_field_set: bad data handle");
    assert_non_zero(unsafe { _field_set(data_handle, data_handle, api::datasources::FieldKind::Uint32 as u32, 1234) }, "_field_set: bad field handle");

    let mut err: u32 = 0;
    let err_ptr = &mut err as *mut u32 as u32;
    let ret = unsafe {_field_get_scalar(field_handle, data_handle, api::datasources::FieldKind::Uint32 as u32, err_ptr) };
    assert_equal(ret, 1234, "_field_get_scalar: ok");
    assert_zero(err, "_field_get_scalar: ok");

    unsafe { _field_get_scalar(field_handle, data_handle, 1005, err_ptr) };
    assert_equal(err, 1, "_field_get_scalar: bad kind");

    unsafe {_field_get_scalar(field_handle, field_handle, api::datasources::FieldKind::Uint32 as u32, err_ptr) };
    assert_equal(err, 1, "_field_get_scalar: bad data handle");

    unsafe { _field_get_scalar(data_handle, data_handle, api::datasources::FieldKind::Uint32 as u32, err_ptr) };
    assert_equal(err, 1, "_field_get_scalar: bad field handle");

    // a zero err ptr shouldn't cause any crash
    unsafe { _field_get_scalar(field_handle, data_handle, 1005, 0) };

    /* Params */
    let param_buf = bytes_to_buf_ptr(&vec![0u8; 512]);
    assert_non_zero(unsafe { _get_param_value(string_to_buf_ptr("non-existing-param"), param_buf) }, "_get_param_value: not-found");
    assert_non_zero(unsafe { _get_param_value(INVALID_STR_PTR, param_buf) }, "_get_param_value: invalid key ptr");

    /* Config */
    assert_zero(unsafe { _set_config(string_to_buf_ptr("key"), string_to_buf_ptr("value"), api::datasources::FieldKind::String as u32) }, "_set_config: ok");
    assert_non_zero(unsafe { _set_config(string_to_buf_ptr("key"), string_to_buf_ptr("value"), 1005) }, "_set_config: bad kind");
    assert_non_zero(unsafe { _set_config(INVALID_STR_PTR, string_to_buf_ptr("value"), api::datasources::FieldKind::String as u32) }, "_set_config: bad key ptr");
    assert_non_zero(unsafe { _set_config(string_to_buf_ptr("key"), INVALID_STR_PTR, api::datasources::FieldKind::String as u32) }, "_set_config: bad value ptr");

    /* Map */
    assert_zero(unsafe { _map_get(INVALID_STR_PTR) }, "_map_get: bad map pointer");
    assert_non_zero(unsafe { _map_update(0, INVALID_STR_PTR, INVALID_STR_PTR, 0) }, "_map_update: bad handle");
    assert_non_zero(unsafe { _map_lookup(0, INVALID_STR_PTR, INVALID_STR_PTR) }, "_map_lookup: bad handle");
    assert_non_zero(unsafe { _map_delete(0, INVALID_STR_PTR) }, "_map_delete: bad handle");

    /* SyscallDeclaration */
    let syscall_declaration_size = std::mem::size_of::<SyscallDeclarationRaw>();
    let syscall_declaration_ptr = bytes_to_buf_ptr(&vec![0u8; syscall_declaration_size]);
    let invalid_syscall_declaration_ptr = bytes_to_buf_ptr(&vec![0u8; syscall_declaration_size / 2]);
    assert_zero(unsafe { _declaration(string_to_buf_ptr("execve"), syscall_declaration_ptr) }, "_declaration: good");
    assert_non_zero(unsafe { _declaration(INVALID_STR_PTR, syscall_declaration_ptr) }, "_declaration: bad syscall name pointer");
    assert_non_zero(unsafe { _declaration(string_to_buf_ptr("execve"), invalid_syscall_declaration_ptr) }, "_declaration: bad syscall decl pointer");

    /* Kallsyms */
    assert_equal(unsafe { _kallsyms_symbol_exists(INVALID_STR_PTR) }, 0, "_kallsyms_symbol_exists: bad symbol pointer");
    assert_equal(unsafe { _kallsyms_symbol_exists(string_to_buf_ptr("abcde_bad_name")) }, 0, "_kallsyms_symbol_exists: nonexistent symbol name");
    assert_equal(unsafe { _kallsyms_symbol_exists(string_to_buf_ptr("socket_file_ops")) }, 1, "_kallsyms_symbol_exists: good symbol name");

    0
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStart() -> i32 {
    #[repr(C)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct MapTestStruct {
        a: i32,
        b: i32,
        c: i8,
        _pad: [i8; 3],
    }

    let key = MapTestStruct {
        a: 42,
        b: 42,
        c: 43,
        _pad: [0; 3],
    };
    let key_ptr = any_to_buf_ptr(&key).expect("Invalid key pointer");

    let handle = unsafe { _map_get(string_to_buf_ptr("test_map")) };
    assert_non_zero(handle, "_map_get: test_map should exist");

    assert_non_zero(unsafe { _map_update(handle, INVALID_STR_PTR, INVALID_STR_PTR, 1<<3) }, "_map_update: bad flag value");
    assert_non_zero(unsafe { _map_update(handle, INVALID_STR_PTR, INVALID_STR_PTR, 0) }, "_map_update: bad key pointer");
    assert_non_zero(unsafe { _map_update(handle, key_ptr, INVALID_STR_PTR, 0) }, "_map_update: bad value pointer");

    assert_non_zero(unsafe { _map_lookup(handle, INVALID_STR_PTR, 0) }, "_map_lookup: bad key pointer");
    assert_non_zero(unsafe { _map_lookup(handle, INVALID_STR_PTR, INVALID_STR_PTR) }, "_map_lookup: bad value pointer");

    assert_non_zero(unsafe { _map_delete(handle, INVALID_STR_PTR) }, "_map_delete: bad key pointer");

    let bad_map = unsafe { _map_new(string_to_buf_ptr("bad_map"), api::map::MapType::Hash as u32, 4, 4, 1) };
    assert_non_zero(bad_map, "newMap: creating map");
    assert_zero(unsafe { _map_release(bad_map) }, "_map_release: closing map");
    assert_non_zero(unsafe { _map_lookup(bad_map, INVALID_STR_PTR, INVALID_STR_PTR) }, "_map_lookup: bad handle");
    assert_non_zero(unsafe { _map_release(bad_map) }, "_map_release: bad handle");

    0
}

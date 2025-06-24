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

use api::{
	datasources::{ DataSource, DataSourceType, Field },
	map::Map,
	perf::PerfReader,
	syscall::SyscallDeclaration,
};
use std::{
	collections::HashMap,
	io::Error,
	sync::{ Arc, LazyLock, Mutex },
	result::Result,
	time::{Duration, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy)]
pub enum EventType {
	Enter = 0,
	Exit = 1,
	Cont = 2,
}

const USE_NULL_BYTE_LENGTH: u64 = 0x0fffffffffffffff;
const USE_RET_AS_PARAM_LENGTH: u64 = 0x0ffffffffffffffe;
const USE_ARG_INDEX_AS_PARAM_LENGTH: u64 = 0x0ffffffffffffff0;
const PARAM_PROBE_AT_EXIT_MASK: u64 = 0xf000000000000000;

const SYSCALL_ARGS: u8 = 6;
// os.Getpagesize() in wasm will return 65536:
// https://cs.opensource.google/go/go/+/master:src/runtime/os_wasm.go;l=13-14?q=physPageSize&ss=go%2Fgo&start=11
// https://webassembly.github.io/spec/core/exec/runtime.html#memory-instances
const LINUX_PAGE_SIZE: u32 = 4096;
// The max entries of the syscall_filters map.
const MAX_SYSCALL_FILTERS: usize = 16;

// TODO Find all syscalls which take a char * as argument and add them there.
static SYSCALL_DEFS: LazyLock<HashMap<&'static str, [u64; 6]>> = LazyLock::new(|| {
	let mut m = HashMap::new();
	m.insert("execve", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("access", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("open", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("openat", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("mkdir", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("chdir", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("pivot_root", [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("mount", [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0]);
	m.insert("umount2", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("sethostname", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("statfs", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("stat", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("statx", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("lstat", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
	m.insert("fgetxattr", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("lgetxattr", [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("getxattr", [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("newfstatat", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
	m.insert("read", [0, USE_RET_AS_PARAM_LENGTH | PARAM_PROBE_AT_EXIT_MASK, 0, 0, 0, 0]);
	m.insert("write", [0, USE_ARG_INDEX_AS_PARAM_LENGTH + 2, 0, 0, 0, 0]);
	m.insert("getcwd", [USE_NULL_BYTE_LENGTH | PARAM_PROBE_AT_EXIT_MASK, 0, 0, 0, 0, 0]);
	m.insert("pread64", [0, USE_RET_AS_PARAM_LENGTH | PARAM_PROBE_AT_EXIT_MASK, 0, 0, 0, 0]);

	m
});

#[derive(Debug)]
struct EventFields {
	mntns_id: Field,
	cpu: Field,
	pid: Field,
	comm: Field,
	syscall: Field,
	parameters: Field,
	ret: Field,
}

impl Default for EventFields {
	fn default() -> Self {
		EventFields{
			mntns_id: Field(0),
			cpu: Field(0),
			pid: Field(0),
			comm: Field(0),
			syscall: Field(0),
			parameters: Field(0),
			ret: Field(0),
		}
	}
}

static DS_OUTPUT: LazyLock<Mutex<DataSource>> = LazyLock::new(|| {
	let ds = match DataSource::new_datasource("traceloop".to_string(), DataSourceType::Single) {
		Ok(ds) => ds,
		Err(err) => panic!("{:?}", err)
	};

	Mutex::new(ds)
});

static FIELDS: LazyLock<Mutex<EventFields>> = LazyLock::new(|| Mutex::new(EventFields::default()));

struct ContainerRingReader {
	inner_buffer: Map,
	perf_reader: PerfReader,
}

struct Tracelooper<'a> {
	map_of_perf_buffers: Map,
	readers: Mutex<HashMap<u64, &'a ContainerRingReader>>
}

impl Default for Tracelooper<'_> {
	fn default() -> Self {
		let map_name = "map_of_perf_buffers";
		let map_of_perf_buffers = match Map::get(map_name) {
			Ok(m) => m,
			Err(err) => panic!("{}", err),
		};

		Tracelooper{
			map_of_perf_buffers: map_of_perf_buffers,
			readers: Mutex::new(HashMap::new())
		}
	}

	// todo!
}

static TRACELOOPER: LazyLock<Mutex<Tracelooper>> = LazyLock::new(|| Mutex::new(Tracelooper::default()));

// Keep in sync with type in program.bpf.c.
#[repr(C)]
struct TraceloopSyscallEventContT {
	event_type: EventType,
	param: [u8; 128],
	monotonic_ts: u64,
	length: u64,
	index: u8,
	failed: u8,
	_padding: [u8; 5],
}

// Keep in sync with type in program.bpf.c.
#[repr(C)]
struct traceloopSyscallEventT {
	event_type: EventType,
	args: [u64; 6],
	monotonic_ts: u64,
	boot_ts: u64,
	pid: u32,
	cpu: u16,
	id: u16,
	comm: [u8; 16],
	cont_nr: u8,
	_padding: [u8; 62],
}

#[derive(Debug)]
struct SyscallEvent {
	boot_ts: u64,
	monotonic_ts: u64,
	typ: EventType,
	cont_nr: u8,
	cpu: u16,
	id: u16,
	pid: u32,
	comm: String,
	args: Vec<u64>,
	mount_ns_id: u64,
	retval: u64,
}

#[derive(Debug)]
struct SyscallEventContinued {
	monotonic_ts: u64,
	index: u8,
	param: String,
}

#[derive(Debug)]
struct SyscallParam {
	name:    String,
	value:   String,
	content: String,
}

#[derive(Debug)]
struct Event {
	ts: i64,
	mount_ns_id: u64,
	cpu: u16,
	pid: u32,
	comm: String,
	syscall: String,
	parameters: Vec<SyscallParam>,
	retval: String,
}

struct SyscallCache(HashMap<String, SyscallDeclaration>);

impl SyscallCache {
	pub fn new() -> Self {
		Self { 0: HashMap::new() }
	}

	pub fn get(&mut self, name: String) -> Result<&SyscallDeclaration, String> {
		Ok(self.0.entry(name.clone()).or_insert(api::syscall::get_syscall_declaration(&name)?))
	}
}

fn params_to_string(parameters: Vec<SyscallParam>) -> String {
	let mut ret: String = "".to_string();

	for (idx, p) in parameters.iter().enumerate() {
		ret.push_str(&format!("{}={}", p.name, p.value));

		if idx < parameters.len() - 1 {
			ret.push_str(",");
		}
	}

	ret
}

// This may be uneeded.
fn timestamp_from_event(event: &SyscallEvent) -> i64 {
	let t = UNIX_EPOCH + Duration::new(0, event.boot_ts as u32);
	t.duration_since(UNIX_EPOCH).expect("Time cannot go backward...").as_nanos() as i64
}

// Copied/pasted/adapted from kernel macro round_up:
// https://elixir.bootlin.com/linux/v6.0/source/include/linux/math.h#L25
fn round_up(x: usize, y: usize) -> usize{
	((x - 1) | (y - 1)) + 1
}

// The kernel aligns size of perf event with the following snippet:
// void perf_prepare_sample(...)
//
//	{
//		//...
//		size = round_up(sum + sizeof(u32), sizeof(u64));
//		raw->size = size - sizeof(u32);
//		frag->pad = raw->size - sum;
//		// ...
//	}
//
// (https://elixir.bootlin.com/linux/v6.0/source/kernel/events/core.c#L7353)
// In the case of our structure of interest (i.e. struct_syscall_event_t and
// struct_syscall_event_cont_t), their size will be increased by 4, here is
// an example for struct_syscall_event_t which size is 88:
// size = round_up(sum + sizeof(u32), sizeof(u64))
//
//	= round_up(88 + 4, 8)
//	= round_up(92, 8)
//	= 96
//
// raw->size = size - sizeof(u32)
//
//	= 96 - 4
//	= 92
//
// So, 4 bytes will be added as padding at the end of the event and the size we
// will read getting perfEventSample will be 92 instead of 88.
fn align_size(struct_size: usize) -> usize {
	round_up(struct_size + size_of::<u32>(), size_of::<u64>()) - size_of::<u32>()
}

// Convert a return value to corresponding error number if meaningful.
// See man syscalls:
// Note:
// system calls indicate a failure by returning a negative error
// number to the caller on architectures without a separate error
// register/flag, as noted in syscall(2); when this happens, the
// wrapper function negates the returned error number (to make it
// positive), copies it to errno, and returns -1 to the caller of
// the wrapper.
fn ret_to_str(ret: u64) -> String {
	let errno: i32 = ret as i32;
	if errno >= -4095 && errno <= -1 {
		format!("-1 ({})", Error::from_raw_os_error(-errno))
	} else {
		format!("{}", ret)
	}
}

// Used as cache for getSyscallDeclaration().
static SYSCALL_DECLARATION_CACHE: LazyLock<Mutex<HashMap<String, Arc<SyscallDeclaration>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_syscall_declaration(name: String) -> Result<Arc<SyscallDeclaration>, String> {
	// cache here is a local MutexGuard which exists only until the function end.
	// So, we need to use Arc to be able to get long-lived reference from this
	// function.
	// This may be inefficient but is caused by SYSCALL_DECLARATION_CACHE being
	// static and used as global state.
	// TODO Replace by local cache in read().
	let mut cache = SYSCALL_DECLARATION_CACHE.lock().unwrap();
	match cache.get(&name) {
		Some(declaration) => Ok(Arc::clone(declaration)),
		None => Ok(cache.insert(name.clone(), Arc::new(api::syscall::get_syscall_declaration(&name)?)).unwrap())
	}
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
	// let ds = match DataSource::get_datasource("mount".to_string()) {
	// 	Ok(ds) => ds,
	// 	Err(e) => {
	// 		api::errorf!("failed to get datasource: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let op_raw_field = match ds.get_field("op_raw") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let src_field = match ds.get_field("src") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let dest_field = match ds.get_field("dest") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let fs_field = match ds.get_field("fs") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let data_field = match ds.get_field("data") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let error_raw_field = match ds.get_field("error_raw") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let flags_field = match ds.get_field("flags") {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to get field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let call_field = match ds.add_field("call", FieldKind::String) {
	// 	Ok(f) => f,
	// 	Err(e) => {
	// 		api::errorf!("failed to add field: {:?}", e);
	// 		return 1;
	// 	}
	// };
 //
	// let _ = ds.subscribe(move |_source: DataSource, data: Data| {
	// 	let flags = match flags_field.string(data, 512) {
	// 		Ok(flags) => flags,
	// 		Err(_) => "".to_string(),
	// 	};
	// 	let op_raw = match op_raw_field.get_data(data, FieldKind::Int32) {
	// 		Ok(FieldData::Int32(op_raw)) => op_raw,
	// 		_ => 0,
	// 	};
	// 	let src = match src_field.string(data, 4096) {
	// 		Ok(src) => src,
	// 		Err(_) => "".to_string(),
	// 	};
	// 	let dest = match dest_field.string(data, 4096) {
	// 		Ok(dest) => dest,
	// 		Err(_) => "".to_string(),
	// 	};
	// 	let fs = match fs_field.string(data, 4096) {
	// 		Ok(fs) => fs,
	// 		Err(_) => "".to_string(),
	// 	};
	// 	let data_str = match data_field.string(data, 512) {
	// 		Ok(data_str) => data_str,
	// 		Err(_) => "".to_string(),
	// 	};
	// 	let error_raw = match error_raw_field.get_data(data, FieldKind::Uint32) {
	// 		Ok(FieldData::Uint32(error_raw)) => error_raw,
	// 		_ => 0,
	// 	};
 //
	// 	let _ = call_field.set_data(data, &get_call_str(op_raw, src, dest, fs, flags, data_str, error_raw));
	// }, 0,);
 //
	0
}

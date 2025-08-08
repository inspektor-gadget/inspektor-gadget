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

#![feature(ip_from)]
use api::{
    datasources::{
        Data, DataSource, DataSourceType, Field, FieldKind, Packet, DATA_SOURCE_CONTAINERS,
        DATA_SOURCE_CONTAINERS_EVENT_TYPE_MAX_SIZE,
    },
    fields::FieldData,
    map::{Map, MapSpec, MapType, MapUpdateFlags},
    perf::PerfReader,
    syscall::SyscallDeclaration,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    io::Error,
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    result::Result,
    sync::{LazyLock, Mutex},
    time::{Duration, UNIX_EPOCH},
};

#[repr(u32)] // To be in sync wth C enum size.
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Enter = 0,
    Exit = 1,
    Cont = 2,
}

const USE_NULL_BYTE_LENGTH: u64 = 0x0fff_ffff_ffff_ffff;
const USE_RET_AS_PARAM_LENGTH: u64 = 0x0fff_ffff_ffff_fffe;
const USE_ARG_INDEX_AS_PARAM_LENGTH: u64 = 0x0fff_ffff_ffff_fff0;
const PARAM_PROBE_AT_EXIT_MASK: u64 = 0xf000_0000_0000_0000;

const SYSCALL_ARGS: usize = 6;
// os.Getpagesize() in wasm will return 65536:
// https://cs.opensource.google/go/go/+/master:src/runtime/os_wasm.go;l=13-14?q=physPageSize&ss=go%2Fgo&start=11
// https://webassembly.github.io/spec/core/exec/runtime.html#memory-instances
const LINUX_PAGE_SIZE: u32 = 4096;
// The max entries of the syscall_filters map.
const MAX_SYSCALL_FILTERS: usize = 16;

// Constants from https://pkg.go.dev/syscall
const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// struct sock_addr_* generally have the family as the first field.
const SOCK_ADDR_MIN_SIZE: usize = 2;
// IPv4: struct sockaddr_in
// struct sockaddr_in {
//     sa_family_t    sin_family; // address family: AF_INET
//     in_port_t      sin_port;   // port in network byte order
//     struct in_addr sin_addr;   // internet address
// };
// struct in_addr {
//     uint32_t s_addr; // address in network byte order
// };
const SOCK_ADDR_IN_MIN_SIZE: usize = 8;
// IPv6: struct sockaddr_in6
// struct sockaddr_in6 {
//     sa_family_t     sin6_family;   // AF_INET6
//     in_port_t       sin6_port;     // port number
//     uint32_t        sin6_flowinfo; // IPv6 flow-info
//     struct in6_addr sin6_addr;     // IPv6 address
//     uint32_t        sin6_scope_id; // Scope ID (for link-local addresses)
// };
// struct in6_addr {
//     unsigned char   s6_addr[16];   // IPv6 address in network byte order
// };
const SOCK_ADDR_IN_6_MIN_SIZE: usize = 28;
// Unix domain socket: struct sockaddr_un
// struct sockaddr_un {
//     sa_family_t sun_family; // AF_UNIX
//     char        sun_path[108]; // Pathname
// };
// The path can be abstract (starts with NUL byte) or filesystem path.
// The path can be shorter than 108 bytes but at least 1 byte
const SOCK_ADDR_UN_MIN_SIZE: usize = 3;

// TODO Find all syscalls which take a char * as argument and add them there.
static SYSCALL_DEFS: LazyLock<HashMap<&'static str, [u64; 6]>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("execve", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("access", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("open", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("openat", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
    m.insert("mkdir", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("chdir", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert(
        "pivot_root",
        [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0],
    );
    m.insert(
        "mount",
        [
            USE_NULL_BYTE_LENGTH,
            USE_NULL_BYTE_LENGTH,
            USE_NULL_BYTE_LENGTH,
            0,
            0,
            0,
        ],
    );
    m.insert("umount2", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("sethostname", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("statfs", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("stat", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("statx", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
    m.insert("lstat", [USE_NULL_BYTE_LENGTH, 0, 0, 0, 0, 0]);
    m.insert("fgetxattr", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
    m.insert(
        "lgetxattr",
        [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0],
    );
    m.insert(
        "getxattr",
        [USE_NULL_BYTE_LENGTH, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0],
    );
    m.insert("newfstatat", [0, USE_NULL_BYTE_LENGTH, 0, 0, 0, 0]);
    m.insert(
        "read",
        [
            0,
            USE_RET_AS_PARAM_LENGTH | PARAM_PROBE_AT_EXIT_MASK,
            0,
            0,
            0,
            0,
        ],
    );
    m.insert("write", [0, USE_ARG_INDEX_AS_PARAM_LENGTH + 2, 0, 0, 0, 0]);
    m.insert(
        "getcwd",
        [
            USE_NULL_BYTE_LENGTH | PARAM_PROBE_AT_EXIT_MASK,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    m.insert(
        "pread64",
        [
            0,
            USE_RET_AS_PARAM_LENGTH | PARAM_PROBE_AT_EXIT_MASK,
            0,
            0,
            0,
            0,
        ],
    );
    m.insert(
        "connect",
        [0, USE_ARG_INDEX_AS_PARAM_LENGTH + 2, 0, 0, 0, 0],
    );

    m
});

#[derive(Debug)]
struct EventFields {
    mount_ns_id: Field,
    cpu: Field,
    pid: Field,
    comm: Field,
    syscall: Field,
    parameters: Field,
    ret: Field,
}

impl Default for EventFields {
    fn default() -> Self {
        EventFields {
            mount_ns_id: Field(0),
            cpu: Field(0),
            pid: Field(0),
            comm: Field(0),
            syscall: Field(0),
            parameters: Field(0),
            ret: Field(0),
        }
    }
}

static DS_OUTPUT: LazyLock<DataSource> = LazyLock::new(|| {
    match DataSource::new_datasource("traceloop".to_string(), DataSourceType::Single) {
        Ok(ds) => ds,
        Err(err) => panic!("creating traceloop datasource: {err:?}"),
    }
});

static FIELDS: LazyLock<Mutex<EventFields>> = LazyLock::new(|| Mutex::new(EventFields::default()));

struct Tracelooper {
    map_of_perf_buffers: Map,
    readers: HashMap<u64, PerfReader>,
}

impl Tracelooper {
    fn attach(&mut self, mount_ns_id: u64) -> Result<(), String> {
        // Keep the spec in sync with program.bpf.c.
        let spec = MapSpec {
            name: format!("perf_buffer_{mount_ns_id}"),
            typ: MapType::PerfEventArray,
            key_size: 4u32,
            value_size: 4u32,
            max_entries: 0,
        };

        // 1. Create inner Map as perf buffer.
        let inner_buffer = match Map::new(&spec) {
            Ok(map) => map,
            Err(err) => return Err(format!("creating map {}: {}", spec.name, err)),
        };

        // 2. Use this inner Map to create the perf reader.
        let perf_reader = match PerfReader::new(&inner_buffer, 64 * LINUX_PAGE_SIZE, true) {
            Ok(perf_reader) => perf_reader,
            Err(err) => return Err(format!("creating perf buffer: {err}")),
        };

        // 3. Add the inner map's file descriptor to outer map.
        if let Err(err) = self.map_of_perf_buffers.update(
            &mount_ns_id,
            &inner_buffer,
            MapUpdateFlags::UpdateNoExist,
        ) {
            return Err(format!(
                "adding perf buffer to map with mount_ns_id {mount_ns_id}: {err}"
            ));
        }

        self.readers.insert(mount_ns_id, perf_reader);

        Ok(())
    }

    fn detach(&self, mount_ns_id: u64) -> Result<(), String> {
        match self.map_of_perf_buffers.delete(&mount_ns_id) {
            Ok(()) => Ok(()),
            Err(err) => Err(format!(
                "removing perf buffer from map with mount_ns_id {mount_ns_id}: {err}"
            )),
        }
    }

    fn read(&self, mount_ns_id: u64, perf_reader: &PerfReader) -> Result<Vec<Event>, String> {
        let mut syscall_continued_events_map = HashMap::<u64, Vec<SyscallEventContinued>>::new();
        let mut syscall_enter_events_map = HashMap::<u64, Vec<SyscallEvent>>::new();
        let mut syscall_exit_events_map = HashMap::<u64, Vec<SyscallEvent>>::new();
        let record = [0u8; align_size(size_of::<TraceloopSyscallEventT>())];
        let mut to_delete = HashSet::new();
        let mut events = Vec::new();

        perf_reader.pause()?;

        loop {
            if let Err(err) = perf_reader.read(&record) {
                if err == "deadline exceeded" {
                    break;
                }

                return Err(err);
            }

            let sys_event = unsafe { *(record.as_ptr() as *const TraceloopSyscallEventT) };
            match sys_event.event_type {
                EventType::Enter | EventType::Exit => {
                    let mut event = SyscallEvent {
                        boot_ts: sys_event.boot_ts,
                        monotonic_ts: sys_event.monotonic_ts,
                        typ: sys_event.event_type,
                        cpu: sys_event.cpu,
                        id: sys_event.id,
                        pid: sys_event.pid,
                        comm: api::helpers::from_c_string(&sys_event.comm),
                        mount_ns_id,
                        args: [0u64; SYSCALL_ARGS],
                        retval: 0,
                    };

                    let target: &mut HashMap<u64, Vec<SyscallEvent>>;
                    match event.typ {
                        EventType::Enter => {
                            for i in 0..SYSCALL_ARGS {
                                event.args[i] = sys_event.args[i];
                            }

                            target = &mut syscall_enter_events_map;
                        }
                        EventType::Exit => {
                            event.retval = sys_event.args[0];

                            target = &mut syscall_exit_events_map;
                        }
                        _ => panic!(
                            "excepted {:?} or {:?}, got {:?}",
                            EventType::Enter,
                            EventType::Exit,
                            event.typ
                        ),
                    }

                    target.entry(event.monotonic_ts).or_default().push(event);
                }
                EventType::Cont => {
                    let sys_event_cont =
                        unsafe { *(record.as_ptr() as *const TraceloopSyscallEventContT) };

                    let mut continued_event = SyscallEventContinued {
                        monotonic_ts: sys_event_cont.monotonic_ts,
                        index: sys_event_cont.index,
                        param_raw: sys_event_cont.param,
                        param_raw_length: sys_event_cont.param.len(),
                        param: String::new(),
                    };

                    if sys_event_cont.failed != 0 {
                        continued_event.param = "(Failed to dereference pointer)".to_string();
                    } else if sys_event_cont.length == USE_NULL_BYTE_LENGTH {
                        continued_event.param = api::helpers::from_c_string(&sys_event_cont.param);
                        continued_event.param_raw_length = continued_event.param.len();
                    } else if sys_event_cont.length < sys_event_cont.param.len() as u64 {
                        continued_event.param = String::from_utf8_lossy(
                            &sys_event_cont.param[..sys_event_cont.length as usize],
                        )
                        .into_owned();
                        continued_event.param_raw_length = sys_event_cont.length as usize;
                    } else {
                        continued_event.param =
                            String::from_utf8_lossy(&sys_event_cont.param).into_owned();
                    }

                    continued_event.param =
                        format!("\"{}\"", continued_event.param.escape_default());

                    syscall_continued_events_map
                        .entry(continued_event.monotonic_ts)
                        .or_default()
                        .push(continued_event);
                }
            }
        }

        perf_reader.resume()?;

        let mut syscall_declaration_cache = SyscallDeclarationCache::new();

        // Publish the events we gathered.
        for (enter_ts, enter_ts_events) in syscall_enter_events_map.iter_mut() {
            for enter_event in enter_ts_events {
                let syscall_name = match api::syscall::get_syscall_name(enter_event.id) {
                    Ok(name) => name,
                    Err(err) => return Err(format!("getting syscall name: {err}")),
                };

                let syscall_declaration = match syscall_declaration_cache.get(&syscall_name) {
                    Ok(decl) => decl,
                    Err(err) => return Err(format!("getting syscall definition: {err}")),
                };

                let parameters_number = syscall_declaration.params.len();
                api::debugf!("\tevent parametersNumber: {}", parameters_number);

                let mut event = Event {
                    ts: timestamp_from_event(enter_event),
                    mount_ns_id: enter_event.mount_ns_id,
                    cpu: enter_event.cpu,
                    pid: enter_event.pid,
                    comm: mem::take(&mut enter_event.comm),
                    syscall: syscall_name,
                    parameters: Vec::with_capacity(parameters_number),
                    retval: String::new(),
                };

                for i in 0..parameters_number {
                    let param_name = &syscall_declaration.params[i].name;
                    api::debugf!("\t\tevent paramName: {}", param_name);

                    let is_pointer = syscall_declaration.params[i].is_pointer;
                    let param_value = if is_pointer {
                        format!("{:#x}", enter_event.args[i])
                    } else {
                        enter_event.args[i].to_string()
                    };
                    api::debugf!("\t\tevent paramValue: {}", param_value);

                    let mut syscall_param = SyscallParam {
                        name: param_name.to_string(),
                        value: param_value,
                        content: String::new(),
                    };

                    if let Some(syscall_cont_events) =
                        syscall_continued_events_map.get_mut(enter_ts)
                    {
                        for syscall_cont_event in syscall_cont_events {
                            if usize::from(syscall_cont_event.index) != i {
                                continue;
                            }

                            syscall_param.content =
                                if event.syscall == "connect" && param_name == "uservaddr" {
                                    sockaddr_from_bytes(
                                        &syscall_cont_event.param_raw
                                            [..syscall_cont_event.param_raw_length],
                                    )?
                                } else {
                                    mem::take(&mut syscall_cont_event.param)
                                };

                            break;
                        }
                    }

                    event.parameters.push(syscall_param);
                }

                syscall_continued_events_map.remove(enter_ts);

                // There is no exit event for exit(), exit_group() and rt_sigreturn().
                if event.syscall == "exit"
                    || event.syscall == "exit_group"
                    || event.syscall == "rt_sigreturn"
                {
                    to_delete.insert(*enter_ts);

                    event.retval = "X".to_string();

                    api::debugf!("{:?}", event);
                    events.push(event);

                    continue;
                }

                let Some(exit_ts_events) = syscall_exit_events_map.get(enter_ts) else {
                    api::debugf!("no exit event for timestamp {}", enter_ts);

                    continue;
                };

                for exit_event in exit_ts_events {
                    if enter_event.id != exit_event.id || enter_event.pid != exit_event.pid {
                        continue;
                    }

                    event.retval = ret_to_str(exit_event.retval);

                    to_delete.insert(*enter_ts);
                    syscall_exit_events_map.remove(enter_ts);

                    api::debugf!("{:?}", event);
                    events.push(event);

                    break;
                }
            }
        }

        syscall_enter_events_map.retain(|k, _| !to_delete.contains(k));

        api::debugf!("len(events): {}; len(syscallEnterEventsMap): {}; len(syscallExitEventsMap): {}; len(syscallContinuedEventsMap): {}\n", events.len(), syscall_enter_events_map.len(), syscall_exit_events_map.len(), syscall_continued_events_map.len());

        // It is possible there are some incomplete events for several reasons:
        // 1. Traceloop was started in the middle of a syscall, then we will only get
        //    the exit but not the enter.
        // 2. Traceloop was stopped in the middle of a syscall, then we will only get
        //    the enter but not the exit
        // 3. The buffer is full and so it only remains some exit events and not the
        //    corresponding enter.
        // Rather than dropping these incomplete events, we just add them to the
        // events to be published.
        match gather_incomplete_events(syscall_enter_events_map) {
            Ok(incomplete_events) => events.extend(incomplete_events),
            Err(err) => return Err(format!("gathering incomplete enter events: {err}")),
        }

        match gather_incomplete_events(syscall_exit_events_map) {
            Ok(incomplete_events) => events.extend(incomplete_events),
            Err(err) => return Err(format!("gathering incomplete exit events: {err}")),
        }

        // Sort all events by ascending timestamp.
        events.sort_by(|a, b| a.ts.cmp(&b.ts));

        Ok(events)
    }
}

static TRACELOOPER: LazyLock<Mutex<Tracelooper>> = LazyLock::new(|| {
    let map_name = "map_of_perf_buffers";
    let map_of_perf_buffers = match Map::get(map_name) {
        Ok(m) => m,
        Err(err) => panic!("getting {map_name}: {err}"),
    };

    Mutex::new(Tracelooper {
        map_of_perf_buffers,
        readers: HashMap::new(),
    })
});

// Keep in sync with type in program.bpf.c.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
struct TraceloopSyscallEventT {
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
    cpu: u16,
    id: u16,
    pid: u32,
    comm: String,
    args: [u64; 6],
    mount_ns_id: u64,
    retval: u64,
}

#[derive(Debug)]
struct SyscallEventContinued {
    monotonic_ts: u64,
    index: u8,
    param: String,
    param_raw: [u8; 128],
    param_raw_length: usize,
}

#[derive(Debug)]
struct SyscallParam {
    name: String,
    value: String,
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

struct SyscallDeclarationCache(HashMap<String, SyscallDeclaration>);

impl SyscallDeclarationCache {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&mut self, name: &str) -> Result<&SyscallDeclaration, String> {
        Ok(self
            .0
            .entry(name.to_string())
            .or_insert(api::syscall::get_syscall_declaration(name)?))
    }
}

fn gather_incomplete_events(
    events_map: HashMap<u64, Vec<SyscallEvent>>,
) -> Result<Vec<Event>, String> {
    let mut events = Vec::new();

    for (_, ts_events) in events_map {
        for event in ts_events {
            let syscall_name = match api::syscall::get_syscall_name(event.id) {
                Ok(name) => name,
                Err(err) => return Err(format!("getting syscall name: {err}")),
            };

            let mut incomplete_event = Event {
                ts: timestamp_from_event(&event),
                mount_ns_id: event.mount_ns_id,
                cpu: event.cpu,
                pid: event.pid,
                comm: event.comm,
                syscall: syscall_name,
                parameters: Vec::new(),
                retval: String::new(),
            };

            incomplete_event.retval = match event.typ {
                EventType::Enter => "unfinished".to_string(),
                EventType::Exit => ret_to_str(event.retval),
                _ => {
                    return Err(format!(
                        "unexpected event type: got {:?}, expected {:?} or {:?}",
                        event.typ,
                        EventType::Enter,
                        EventType::Exit
                    ))
                }
            };

            api::debugf!(
                "incomplete_event({}): {:?}\n",
                &incomplete_event.syscall,
                &incomplete_event
            );

            events.push(incomplete_event);
        }
    }

    Ok(events)
}

fn params_to_string(parameters: &[SyscallParam]) -> Result<String, std::fmt::Error> {
    let mut s = String::new();
    let len = parameters.len();
    for (i, p) in parameters.iter().enumerate() {
        let value = if p.content.is_empty() {
            &p.value
        } else {
            &p.content
        };
        write!(
            s,
            "{}={}{}",
            p.name,
            value,
            if i < len - 1 { ", " } else { "" }
        )?;
    }
    Ok(s)
}

// WARNING This may be uneeded.
fn timestamp_from_event(event: &SyscallEvent) -> i64 {
    let t = UNIX_EPOCH + Duration::new(0, event.boot_ts as u32);
    t.duration_since(UNIX_EPOCH)
        .expect("Time cannot go backward...")
        .as_nanos() as i64
}

// Copied/pasted/adapted from kernel macro round_up:
// https://elixir.bootlin.com/linux/v6.0/source/include/linux/math.h#L25
const fn round_up(x: usize, y: usize) -> usize {
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
const fn align_size(struct_size: usize) -> usize {
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
    if (-4095..=-1).contains(&errno) {
        format!("-1 ({})", Error::from_raw_os_error(-errno))
    } else {
        ret.to_string()
    }
}

// sockaddr_from_bytes attempts to convert a byte slice representing a sockaddr
// into a human-readable IP address and port string.
// It handles AF_INET (IPv4), AF_INET6 (IPv6) and AF_UNIX (Unix sockets).
fn sockaddr_from_bytes(data: &[u8]) -> Result<String, String> {
    let size = data.len();
    if size < SOCK_ADDR_MIN_SIZE {
        return Err(format!("sockaddr byte slice too short to determine family, expected at least {SOCK_ADDR_MIN_SIZE}, got: {size}"));
    }

    // The first two bytes of any sockaddr struct typically contain the address family.
    // This is a uint16 in native endianness.
    // IG supports both amd64 and arm64, which are both little endian.
    // TODO Add a way to get host endianess.
    let family = u16::from_le_bytes(data[..2].try_into().unwrap());
    match family {
        AF_INET => {
            if size < SOCK_ADDR_IN_MIN_SIZE {
                return Err(format!("IPv4 sockaddr byte slice too short, expected {SOCK_ADDR_IN_MIN_SIZE}, got : {size}"));
            }

            // Port is in network byte order (big-endian). Convert to host byte order.
            let port = u16::from_be_bytes(data[2..4].try_into().unwrap());

            // IP address is 4 bytes, also in network byte order.
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);

            Ok(format!("{ip}:{port}"))
        }
        AF_INET6 => {
            if size < SOCK_ADDR_IN_6_MIN_SIZE {
                return Err(format!("IPv6 sockaddr byte slice too short, expected {SOCK_ADDR_IN_6_MIN_SIZE}, got: {size}"));
            }

            let port = u16::from_be_bytes(data[2..4].try_into().unwrap());
            // IPv6 address are 16 bytes long.
            let ip = Ipv6Addr::from_octets(data[8..8 + 16].try_into().unwrap());
            // Extract the scope ID (bytes 24-27).
            // On amd64 and arm64, this is little-endian.
            let scope_id = u32::from_le_bytes(data[24..28].try_into().unwrap());

            Ok(if scope_id != 0 {
                format!("[{ip}%{scope_id}]:{port}")
            } else {
                format!("[{ip}]:{port}")
            })
        }
        AF_UNIX => {
            if size < SOCK_ADDR_UN_MIN_SIZE {
                return Err(format!("Unix sockaddr byte slice too short, expected {SOCK_ADDR_UN_MIN_SIZE}, got: {size}"));
            }

            let path_bytes = &data[2..];
            Ok(if path_bytes[0] == 0 {
                // Abstract Unix socket: the path starts with a null byte.
                // `strace` often represents this with an "@" prefix (e.g., `unix:@/tmp/my_socket`).
                format!("unix:@{}", String::from_utf8_lossy(&path_bytes[1..]))
            } else if let Some(null_terminator) = path_bytes.iter().position(|&b| b == 0) {
                // If a null terminator is found, the path is up to that point.
                format!(
                    "unix:{}",
                    String::from_utf8_lossy(&path_bytes[..null_terminator])
                )
            } else {
                // If no null terminator, treat the rest of the slice as the path.
                // This can happen if the buffer is exactly the size of the path.
                format!("unix:{}", String::from_utf8_lossy(path_bytes))
            })
        }
        _ => Err(format!("unsupported address family: {family}")),
    }
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let sys_event_cont_size = size_of::<TraceloopSyscallEventContT>();
    let sys_event_size = size_of::<TraceloopSyscallEventT>();

    if sys_event_size != sys_event_cont_size {
        api::errorf!(
            "event sizes must be the same, there is a mismatch: {} != {}",
            sys_event_size,
            sys_event_cont_size
        );
        return 1;
    }

    struct FieldInfo<'a> {
        name: &'a str,
        kind: FieldKind,
        field: *mut Field,
    }

    let mut fields = FIELDS.lock().unwrap();
    let fields_info = vec![
        FieldInfo {
            name: "mntns_id",
            kind: FieldKind::Uint64,
            field: &mut fields.mount_ns_id,
        },
        FieldInfo {
            name: "cpu",
            kind: FieldKind::Uint16,
            field: &mut fields.cpu,
        },
        FieldInfo {
            name: "pid",
            kind: FieldKind::Uint32,
            field: &mut fields.pid,
        },
        FieldInfo {
            name: "comm",
            kind: FieldKind::String,
            field: &mut fields.comm,
        },
        FieldInfo {
            name: "syscall",
            kind: FieldKind::String,
            field: &mut fields.syscall,
        },
        FieldInfo {
            name: "parameters",
            kind: FieldKind::String,
            field: &mut fields.parameters,
        },
        FieldInfo {
            name: "ret",
            kind: FieldKind::String,
            field: &mut fields.ret,
        },
    ];
    for field_info in fields_info {
        let name = &field_info.name;
        match DS_OUTPUT.add_field(name, field_info.kind) {
            Ok(field) => unsafe { *field_info.field = field },
            Err(err) => {
                api::errorf!("adding {} field: {:?}", name, err);
                return 1;
            }
        }
    }

    if let Err(err) = fields.mount_ns_id.add_tag("type:gadget_mntns_id") {
        api::errorf!("adding tag to mntns_id field: {}", err);
        return 1;
    }

    0
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStart() -> i32 {
    let syscall_filter_param =
        match api::params::get_param_value("syscall-filters".to_string(), 256) {
            Ok(param_string) => param_string,
            Err(err) => {
                api::errorf!("getting parameter value: {}", err);
                return 1;
            }
        };

    let syscalls_filter_map_name = "syscall_filters";
    let syscalls_filter_map = match Map::get(syscalls_filter_map_name) {
        Ok(map) => map,
        Err(err) => {
            api::errorf!("finding map {}: {}", syscalls_filter_map_name, err);
            return 1;
        }
    };

    let syscall_filters = if syscall_filter_param.is_empty() {
        vec![]
    } else {
        syscall_filter_param.split(',').collect()
    };
    // Keep this in sync with eBPF code.
    if syscall_filters.len() > MAX_SYSCALL_FILTERS {
        api::errorf!(
            "Length of --syscall-filters exceeded. No more than {} values can be added.",
            MAX_SYSCALL_FILTERS
        );
        return 1;
    }

    for name in &syscall_filters {
        let id = match api::syscall::get_syscall_id(name) {
            Ok(id) => id,
            Err(err) => {
                api::errorf!("syscall {} does not exist: {}", name, err);
                return 1;
            }
        };

        if let Err(err) = syscalls_filter_map.put(&id, &true) {
            api::errorf!("adding {} ({}) to syscall filter map: {}", name, id, err);
            return 1;
        }
    }

    if !syscall_filters.is_empty() {
        let syscalls_enable_filter_map_name = "syscall_enable_filters";
        let syscalls_enable_filter_map = match Map::get(syscalls_enable_filter_map_name) {
            Ok(map) => map,
            Err(err) => {
                api::errorf!("finding map {}: {}", syscalls_enable_filter_map_name, err);
                return 1;
            }
        };

        if let Err(err) = syscalls_enable_filter_map.put(&1, &true) {
            api::errorf!("enabling syscall filter: {}", err);
            return 1;
        }
    }

    let syscalls_map_name = "syscalls";
    let syscalls_map = match Map::get(syscalls_map_name) {
        Ok(map) => map,
        Err(err) => {
            api::errorf!("finding map {}: {}", syscalls_map_name, err);
            return 1;
        }
    };

    // Fill the syscall map with specific syscall signatures.
    for (name, def) in SYSCALL_DEFS.iter() {
        // It's possible that the syscall doesn't exist for this architecture, skip it
        let Ok(id) = api::syscall::get_syscall_id(name) else {
            continue;
        };

        if let Err(err) = syscalls_map.put(&(id as u64), def) {
            api::errorf!("storing {} definition in corresponding map: {}", name, err);
            return 1;
        }
    }

    let ds = match DataSource::get_datasource(DATA_SOURCE_CONTAINERS.to_string()) {
        Ok(ds) => ds,
        Err(err) => {
            api::errorf!("finding datasource {}: {:?}", DATA_SOURCE_CONTAINERS, err);
            return 1;
        }
    };

    let event_type_field = match ds.get_field("event_type") {
        Ok(field) => field,
        Err(err) => {
            api::errorf!("getting event_type field: {:?}", err);
            return 1;
        }
    };

    let mount_ns_id_field = match ds.get_field("mntns_id") {
        Ok(field) => field,
        Err(err) => {
            api::errorf!("getting mntns_id field: {:?}", err);
            return 1;
        }
    };

    let name_field = match ds.get_field("name") {
        Ok(field) => field,
        Err(err) => {
            api::errorf!("getting name field: {:?}", err);
            return 1;
        }
    };

    let err = ds.subscribe(
        move |_source: DataSource, data: Data| {
            let event_type = match event_type_field
                .string(data, DATA_SOURCE_CONTAINERS_EVENT_TYPE_MAX_SIZE as u32)
            {
                Ok(event_type) => event_type,
                Err(err) => {
                    api::errorf!("getting event_type from corresponding field: {}", err);
                    return;
                }
            };

            let mount_ns_id = match mount_ns_id_field.get_data(data, FieldKind::Uint64) {
                Ok(FieldData::Uint64(mount_ns_id)) => mount_ns_id,
                Err(err) => {
                    api::errorf!("getting mntns_id from corresponding field: {}", err);
                    return;
                }
                _ => {
                    api::errorf!("getting mntns_id from corresponding field: bad type");
                    return;
                }
            };

            let name = match name_field.string(data, 64) {
                Ok(name) => name,
                Err(err) => {
                    api::errorf!("getting name from corresponding field: {}", err);
                    return;
                }
            };

            let mut tracelooper = TRACELOOPER.lock().unwrap();
            match event_type.as_str() {
                "CREATED" => {
                    api::debugf!("attaching {}", name);
                    if let Err(err) = tracelooper.attach(mount_ns_id) {
                        api::errorf!("attaching container {}: {}", name, err);
                    }
                }
                "DELETED" => {
                    api::debugf!("attaching {}", name);
                    if let Err(err) = tracelooper.detach(mount_ns_id) {
                        api::errorf!("detaching container {}: {}", name, err);
                    }
                }
                // Nothing to do, we don't care about other events.
                _ => (),
            }
        },
        0,
    );

    if let Err(err) = &err {
        api::errorf!("subscribing to datasource: {:?}", err);
        return 1;
    }

    0
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStop() -> i32 {
    let tracelooper = TRACELOOPER.lock().unwrap();
    let fields = FIELDS.lock().unwrap();

    for (mount_ns_id, reader) in &tracelooper.readers {
        let events = match tracelooper.read(*mount_ns_id, reader) {
            Ok(events) => events,
            Err(err) => {
                api::errorf!("reading container: {}", err);
                continue;
            }
        };

        for event in events {
            let packet = match DS_OUTPUT.new_packet_single() {
                Ok(packet) => packet,
                Err(err) => {
                    api::errorf!("creating datasource packet: {:?}", err);
                    continue;
                }
            };

            let packet_data = Data(packet.0);

            if let Err(err) = fields.mount_ns_id.set_data(packet_data, &event.mount_ns_id) {
                api::errorf!("setting mount_ns_id in packet: {:?}", err);
            }
            if let Err(err) = fields.cpu.set_data(packet_data, &event.cpu) {
                api::errorf!("setting cpu in packet: {:?}", err);
            }
            if let Err(err) = fields.pid.set_data(packet_data, &event.pid) {
                api::errorf!("setting pid in packet: {:?}", err);
            }
            if let Err(err) = fields.comm.set_data(packet_data, &event.comm) {
                api::errorf!("setting comm in packet: {:?}", err);
            }
            if let Err(err) = fields.syscall.set_data(packet_data, &event.syscall) {
                api::errorf!("setting syscall in packet: {:?}", err);
            }
            match params_to_string(&event.parameters) {
                Err(err) => api::errorf!("converting parameters to string: {:?}", err),
                Ok(params) => {
                    if let Err(err) = fields.parameters.set_data(packet_data, &params) {
                        api::errorf!("setting parameters in packet: {:?}", err);
                    }
                }
            }
            if let Err(err) = fields.ret.set_data(packet_data, &event.retval) {
                api::errorf!("setting retval in packet: {:?}", err);
            }

            if let Err(err) = DS_OUTPUT.emit_and_release(Packet(packet.0)) {
                api::errorf!("emitting and releasing packet: {:?}", err);
            }
        }
    }

    0
}

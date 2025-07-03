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
    errorf, info,
    map::Map, perf::PerfReader,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
struct Event {
    a: u32,
    b: u32,
    c: u8,
    _unused: [u8; 247],
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStart() -> i32 {
    let map_name = "events";
    let sample = [0u8; 4096];
    let Ok(perf_array) = Map::get(map_name) else {
        errorf!("{} map exists", map_name);
        return 1;
    };

    let Ok(perf_reader) = PerfReader::new(&perf_array, 4096, true) else {
        errorf!("creating perf reader");
        return 1;
    };

    if let Ok(_) = perf_reader.read(&sample) {
        errorf!("perf over writable reader must be paused before reading");
        return 1;
    }

    for _ in 0..10 {
        // Let's generate some events by calling indirectly the write() syscall.
        info!("testing perf array");
    }

    if let Err(_) = perf_reader.pause() {
        errorf!("pausing perf reader");
        return 1;
    }

    if let Err(_) = perf_reader.read(&sample) {
        errorf!("reading perf record");
        return 1;
    }

    let ev = sample.as_ptr() as *const Event;
    let evv = unsafe { *ev };
    let expected_event = Event {
        a: 42,
        b: 42,
        c: 43,
        _unused: [0; 247],
    };
    if evv != expected_event {
        errorf!(
            "record read mismatch: expected {:?}, got {:?}",
            expected_event,
            evv
        );
        return 1;
    }

    if let Err(_) = perf_reader.resume() {
        errorf!("resuming perf reader");
        return 1;
    }

    0
}

use api::{
    errorf,
    ig::{log::LogLevel, map::Map, perf::PerfReader},
    info,
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
fn gadgetAPIVersion() -> u64 {
    1
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    return 0;
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStart() -> i32 {
    let map_name = "events";
    let sample = [0u8; 4096];
    let perf_array: Map;
    match Map::get(map_name) {
        Ok(array) => perf_array = array,
        Err(_) => {
            errorf!("{} map exists", map_name);
            return 1;
        }
    }

    let perf_reader: PerfReader;
    match PerfReader::new(perf_array, 4096, true) {
        Ok(val) => {
            perf_reader = val;
        }
        Err(_) => {
            errorf!("creating perf reader");
            return 1;
        }
    }

    match perf_reader.read(&sample) {
        Ok(_) => {
            errorf!("perf over writable reader must be paused before reading");
            return 1;
        }
        Err(_) => {}
    }

    for _ in 0..10 {
        // Let's generate some events by calling indirectly the write() syscall.
        info!("testing perf array");
    }

    match perf_reader.pause() {
        Ok(_) => {}
        Err(_) => {
            errorf!("pausing perf reader");
            return 1;
        }
    }

    match perf_reader.read(&sample) {
        Ok(_) => {}
        Err(_) => {
            errorf!("reading perf record");
            return 1;
        }
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

    match perf_reader.resume() {
        Ok(_) => {}
        Err(_) => {
            errorf!("resuming perf reader");
            return 1;
        }
    }

    0
}

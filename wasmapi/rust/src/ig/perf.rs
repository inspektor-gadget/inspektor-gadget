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

use crate::ig::helpers::bytes_to_buf_ptr;
use crate::ig::map::Map;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Copy)]
pub struct PerfReader(pub u32);

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "newPerfReader"]
    fn _new(map_handle: u32, size: u32, is_overwritable: u32) -> u32;

    #[link_name = "perfReaderPause"]
    fn _pause(handle: u32) -> u32;

    #[link_name = "perfReaderResume"]
    fn _resume(handle: u32) -> u32;

    #[link_name = "perfReaderRead"]
    fn _read(handle: u32, dst: u64) -> u32;

    #[link_name = "perfReaderClose"]
    fn _close(handle: u32) -> u32;
}

impl PerfReader {
    pub fn new(map: Map, size: u32, is_overwritable: bool) -> Result<Self> {
        let flag = if is_overwritable { 1 } else { 0 };
        let handle = unsafe { _new(map.0, size, flag) };
        if handle == 0 {
            Err(String::from("failed to create perf reader"))
        } else {
            Ok(PerfReader(handle))
        }
    }

    pub fn pause(&self) -> Result<()> {
        let ret = unsafe { _pause(self.0) };
        if ret != 0 {
            Err(String::from("failed to pause perf reader"))
        } else {
            Ok(())
        }
    }

    pub fn resume(&self) -> Result<()> {
        let ret = unsafe { _resume(self.0) };
        if ret != 0 {
            Err(String::from("failed to resume perf reader"))
        } else {
            Ok(())
        }
    }

    pub fn read(&self, dst: &[u8]) -> Result<()> {
        let ptr = bytes_to_buf_ptr(dst);
        let ret = unsafe { _read(self.0, ptr) };
        match ret {
            0 => Ok(()),
            1 => Err(String::from("reading perf reader record")),
            2 => Err(String::from("deadline exceeded")),
            _ => Err(format!("bad return value: expected 0, 1 or 2, got {}", ret)),
        }
    }

    pub fn close(&self) -> Result<()> {
        let ret = unsafe { _close(self.0) };
        if ret != 0 {
            Err(String::from("failed to close perf reader"))
        } else {
            Ok(())
        }
    }
}

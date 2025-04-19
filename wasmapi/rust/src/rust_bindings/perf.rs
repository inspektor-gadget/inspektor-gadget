// Copyright 2024 The Inspektor Gadget authors
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

use crate::rust_bindings::helpers::bytes_to_buf_ptr;
use crate::rust_bindings::map::Map;
use std::io::{Error, ErrorKind, Result as IoResult};
pub type Result<T> = std::result::Result<T, PerfError>;

pub enum PerfError {
    ErrCreatePerf(String),
    ErrPerfPause(String),
    ErrPerfResume(String),
    ErrPerfRead(String),
    ErrPerfClose(String),
}

#[derive(Debug, Clone, Copy)]
pub struct PerfReader(pub u32);

extern "C" {
    #[link_name = "newPerfReader"]
    fn new_perf_reader(map_handle: u32, size: u32, is_overwritable: u32) -> u32;

    #[link_name = "perfReaderPause"]
    fn perf_reader_pause(handle: u32) -> u32;

    #[link_name = "perfReaderResume"]
    fn perf_reader_resume(handle: u32) -> u32;

    #[link_name = "perfReaderRead"]
    fn perf_reader_read(handle: u32, dst: u64) -> u32;

    #[link_name = "perfReaderClose"]
    fn perf_reader_close(handle: u32) -> u32;
}

pub fn new(map: Map, size: u32, is_overwritable: bool) -> Result<PerfReader> {
    let flag = if is_overwritable { 1 } else { 0 };
    let handle = unsafe { new_perf_reader(map.0, size, flag) };
    if handle == 0 {
        return Err(PerfError::ErrCreatePerf(String::from(
            "failed to create perf reader",
        )));
    }
    Ok(PerfReader(handle))
}

impl PerfReader {
    pub fn pause(&self) -> Result<()> {
        let ret = unsafe { perf_reader_pause(self.0) };
        if ret != 0 {
            return Err(PerfError::ErrPerfPause(String::from(
                "failed to pause perf reader",
            )));
        }
        Ok(())
    }

    pub fn resume(&self) -> Result<()> {
        let ret = unsafe { perf_reader_resume(self.0) };
        if ret != 0 {
            return Err(PerfError::ErrPerfResume(String::from(
                "failed to resume perf reader",
            )));
        }
        Ok(())
    }

    pub fn read(&self, dst: &[u8]) -> IoResult<()> {
        let ptr = bytes_to_buf_ptr(dst);
        let ret = unsafe { perf_reader_read(self.0, ptr) };
        match ret {
            0 => Ok(()),
            1 => Err(Error::new(ErrorKind::Other, "reading perf reader record")),
            2 => Err(Error::new(ErrorKind::TimedOut, "deadline exceeded")),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("bad return value: expected 0, 1 or 2, got {}", ret),
            )),
        }
    }

    pub fn close(&self) -> Result<()> {
        let ret = unsafe { perf_reader_close(self.0) };
        if ret != 0 {
            return Err(PerfError::ErrPerfClose(String::from(
                "failed to close perf reader",
            )));
        }
        Ok(())
    }
}

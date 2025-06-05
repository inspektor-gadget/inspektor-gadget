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

use std::{mem, slice};

#[derive(Copy, Clone)]
pub struct BufPtr(pub u64);

pub fn string_to_buf_ptr(s: &str) -> BufPtr {
    if s.is_empty() {
        return BufPtr(0);
    }
    let ptr = s.as_ptr() as u32;

    let len = s.len() as u32;

    BufPtr((u64::from(len) << 32) | u64::from(ptr))
}
/*
any_to_buf_ptr returns a bufPtr that encodes the pointer and length of the
input.
The input is first encoded to binary buffer, which is then used as the
returned bufPtr.
WARNING the binary encoding will only work on fixed size data, *i.e.* with
int32 but not with int, as this data would be exchanged from 32 bits WASM VM
to host which can be 64 bits.
WARNING T has to mimic kernel representation of data structure by
adding padding if needed.
*/
pub fn any_to_buf_ptr<T>(val: &T) -> Result<BufPtr, String> {
    let size = mem::size_of_val(val);
    if size == 0 {
        return Err(String::from("zero-sized types not supported"));
    }
    let ptr = val as *const T as *const u8;
    let bytes = unsafe { slice::from_raw_parts(ptr, size) };

    let buf_ptr = bytes_to_buf_ptr(bytes);

    Ok(buf_ptr)
}

pub fn any_to_buf_ptr_mut<T>(val: &mut T) -> Result<BufPtr, String> {
    let size = std::mem::size_of_val(val);
    if size == 0 {
        return Err(String::from("zero-sized types not supported"));
    }

    let ptr = val as *mut T as *mut u8;
    let bytes = unsafe { std::slice::from_raw_parts_mut(ptr, size) };

    Ok(bytes_to_buf_ptr(bytes))
}

pub fn bytes_to_buf_ptr(b: &[u8]) -> BufPtr {
    let len = b.len() as u64;
    let ptr = b.as_ptr() as u64;
    BufPtr((len << 32) | ptr)
}

pub fn from_c_string(input: &[u8]) -> String {
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    String::from_utf8_lossy(&input[..end]).into_owned()
}

impl BufPtr {
    pub fn bytes(&self) -> Option<Vec<u8>> {
        if self.0 == 0 {
            return None;
        }

        let ptr = (self.0 & 0xFFFF_FFFF) as usize as *const u8;
        let len = (self.0 >> 32) as usize;

        if ptr.is_null() || len == 0 {
            return None;
        }

        // Create a slice from raw parts and clone it to a Vec
        let slice = unsafe { slice::from_raw_parts(ptr, len) };
        Some(slice.to_vec())
    }
}

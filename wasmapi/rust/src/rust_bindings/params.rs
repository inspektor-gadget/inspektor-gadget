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

use crate::rust_bindings::helpers::{bytes_to_buf_ptr, from_c_string, string_to_buf_ptr};

extern "C" {
    #[link_name = "getParamValue"]
    fn get_param_val(key: u64, dst: u64) -> u32;
}

pub fn get_param_value(key: String, max_size: u64) -> Result<String, String> {
    let mut dst = vec![0u8; max_size as usize];

    let key_ptr = string_to_buf_ptr(&key);
    let dst_ptr = bytes_to_buf_ptr(&dst);

    let result = unsafe { get_param_val(key_ptr, dst_ptr) };
    if result == 1 {
        return Err("error getting param value".to_string());
    }

    Ok(from_c_string(&dst))
}

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

use crate::rust_bindings::datasources::FieldKind;
use crate::rust_bindings::helpers::string_to_buf_ptr;

extern "C" {
    #[link_name = "setConfig"]
    fn set_Config(key: u64, val: u64, kind: u32) -> u32;
}
pub trait Allowed {
    fn to_buf_ptr(&self) -> u64;
}

impl Allowed for String {
    fn to_buf_ptr(&self) -> u64 {
        string_to_buf_ptr(self)
    }
}

pub fn set_config<T: Allowed>(key: String, val: &T) -> Result<(), String> {
    let key_ptr = string_to_buf_ptr(&key);
    let val_ptr = val.to_buf_ptr();

    let ret = unsafe { set_Config(key_ptr, val_ptr, FieldKind::String as u32) };
    if ret != 0 {
        return Err("setting config".into());
    }

    Ok(())
}

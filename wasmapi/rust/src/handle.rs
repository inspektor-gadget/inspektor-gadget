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

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "releaseHandle"]
    fn _release_handle(handle: u32) -> u32;
}

pub type Result<T> = std::result::Result<T, String>;

pub fn release_handle<T: Into<u32>>(h: T) -> Result<()> {
    let ret = unsafe { _release_handle(h.into()) };
    if ret != 0 {
        Err("error releasing handle".to_string())
    } else {
        Ok(())
    }
}

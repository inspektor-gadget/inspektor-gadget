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

use api::datasources::FieldKind;
const INVALID_PTR: u32 = 17 * 1024 * 1024;

#[link(wasm_import_module = "ig")]
extern "C" {
    fn fieldGetScalar(acc: u32, data: u32, kind: u32, err_ptr: u32) -> u64;
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    unsafe {
        fieldGetScalar(55, 55, FieldKind::Uint32 as u32, INVALID_PTR);
    }
    panic!("This should never be reached");
}

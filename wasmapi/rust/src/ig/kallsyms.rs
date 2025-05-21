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

use crate::ig::helpers::string_to_buf_ptr;

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "kallsymsSymbolExists"]
    fn _kallsyms_symbol_exists(symbol: u64) -> u32;
}

pub fn kallsyms_symbol_exists(symbol: &str) -> bool {
    let ret = unsafe { _kallsyms_symbol_exists(string_to_buf_ptr(symbol)) };
    ret != 0
}

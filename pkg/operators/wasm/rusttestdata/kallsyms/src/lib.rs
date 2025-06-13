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

use api::errorf;
use api::{kallsyms, log::LogLevel};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let mut exists = kallsyms::kallsyms_symbol_exists("abcde_this_symbol_does_not_exist");
    if exists {
        errorf!("kallsyms_symbol_exists wrongly found symbol");
        return 1;
    }

    exists = kallsyms::kallsyms_symbol_exists("socket_file_ops");
    if !exists {
        errorf!("kallsyms_symbol_exists did not find symbol");
        return 1;
    }

    return 0;
}

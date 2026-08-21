// Copyright 2026 The Inspektor Gadget authors
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

use api::{config, errorf, kallsyms};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    // openat2() was added in kernel 5.6:
    // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fddb5d430ad9
    if !kallsyms::kallsyms_symbol_exists("do_sys_openat2") {
        if let Err(e) = config::set_config(
            "programs.ig_openat2_e.attach_to".to_string(),
            "gadget_program_disabled".to_string(),
        ) {
            errorf!("disabling ig_openat2_e: {:?}", e);
            return 1;
        }

        if let Err(e) = config::set_config(
            "programs.ig_openat2_x.attach_to".to_string(),
            "gadget_program_disabled".to_string(),
        ) {
            errorf!("disabling ig_openat2_x: {:?}", e);
            return 1;
        }
    }

    0
}

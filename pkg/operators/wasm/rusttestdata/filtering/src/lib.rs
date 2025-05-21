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

use api::{
    errorf,
    ig::{filter::should_discard_mntns_id, log::LogLevel},
};

const MNTNS_DISCARDED: u64 = 555;
const MNTNS_NOT_DISCARDED: u64 = 777;

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetAPIVersion() -> u64 {
    1
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    0
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStart() -> i32 {
    if !should_discard_mntns_id(MNTNS_DISCARDED) {
        errorf!("mntns should be discarded");
        return 1;
    }
    if should_discard_mntns_id(MNTNS_NOT_DISCARDED) {
        errorf!("mntns should not be discarded");
        return 1;
    }
    0
}

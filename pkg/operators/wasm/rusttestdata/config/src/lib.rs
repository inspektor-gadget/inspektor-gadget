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
    {config::set_config, log::LogLevel},
};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    if let Err(err) = set_config("foo.bar.zas".to_string(), "myvalue".to_string()) {
        errorf!("SetConfig failed: {:?}", err);
        return 1;
    }
    // set_config only allows string to be passed as a parameter, so due to check enforced during
    // compile time, we do not write test for other datatypes.
    0
}

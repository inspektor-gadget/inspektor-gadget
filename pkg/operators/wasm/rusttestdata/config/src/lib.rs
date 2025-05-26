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

    // This should fail at compile time as the value is not a string
    let invalid_result = set_config("foo.bar.zas".to_string(), 42);

    if let Ok(_) = invalid_result {
        errorf!("SetConfig should have failed");
        return 1;
    }

    0
}

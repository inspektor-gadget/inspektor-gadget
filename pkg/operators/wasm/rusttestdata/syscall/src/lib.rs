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
    syscall::{get_syscall_declaration, get_syscall_id, get_syscall_name},
};

const UNKNOWN_SYSCALL_ID: u16 = 1337;
const OPEN_TREE_SYSCALL_ID: u16 = 428;

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let mut syscall_id: u16 = UNKNOWN_SYSCALL_ID;
    let Ok(mut syscall_name) = get_syscall_name(syscall_id) else {
        errorf!("failed to get name for syscall ID {}", syscall_id);
        return 1;
    };

    // Check behavior is conform with strace
    let expected_syscall_name = format!("syscall_{:x}", syscall_id);

    if syscall_name != expected_syscall_name {
        errorf!(
            "mismatch for syscall {}: expected {}, got {}",
            syscall_id,
            expected_syscall_name,
            syscall_name
        );
        return 1;
    }

    syscall_id = OPEN_TREE_SYSCALL_ID;
    let Ok(name) = get_syscall_name(syscall_id) else {
        errorf!("failed to get name for syscall ID {}", syscall_id);
        return 1;
    };
    syscall_name = name;

    let expected_syscall_name = "open_tree".to_string();

    if syscall_name != expected_syscall_name {
        errorf!(
            "mismatch for syscall {}: expected {}, got {}",
            syscall_id,
            expected_syscall_name,
            syscall_name
        );
        return 1;
    }

    // open_tree has the same ID for both amd64 and arm64.
    syscall_name = "open_tree".to_string();
    let Ok(id) = get_syscall_id(&syscall_name) else {
        errorf!("failed to get ID for syscall {}", syscall_name);
        return 1;
    };

    if id as u16 != OPEN_TREE_SYSCALL_ID {
        errorf!(
            "mismatch for syscall {}: expected {}, got {}",
            syscall_name,
            OPEN_TREE_SYSCALL_ID,
            id
        );
        return 1;
    }

    // Test invalid syscall name
    let syscall_name = "foobar".to_string();
    if let Ok(val) = get_syscall_id(&syscall_name) {
        errorf!(
            "expected no syscall ID for syscall {}, got {}",
            syscall_name,
            val
        );
        return 1;
    }

    if let Ok(val) = get_syscall_declaration(&syscall_name) {
        errorf!(
            "expected no declaration for syscall {}, but got {:?}",
            syscall_name,
            val
        );
        return 1;
    }

    let syscall_name = "execve".to_string();
    let Ok(declaration) = get_syscall_declaration(&syscall_name) else {
        errorf!("failed to get declaration for syscall {}", syscall_name);
        return 1;
    };

    let param_count = declaration.params.len();
    let expected_param_count = 3;

    if param_count != expected_param_count {
        errorf!(
            "syscall {} has {} parameters, got {}",
            syscall_name,
            expected_param_count,
            param_count
        );
        return 1;
    }

    let param_name: String = declaration.params[0].name.clone();
    let expected_param_name = "filename".to_string();
    if param_name != expected_param_name {
        errorf!(
            "syscall {}, first parameter is named {}, got {}",
            syscall_name,
            expected_param_name,
            param_name
        );
        return 1;
    }

    if !declaration.params[0].is_pointer {
        errorf!(
            "in {}, parameter {} is expected to be a pointer",
            syscall_name,
            param_name
        );
        return 1;
    }

    0
}

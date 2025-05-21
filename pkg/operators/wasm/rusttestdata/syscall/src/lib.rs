use api::{
    errorf,
    ig::{
        log::LogLevel,
        syscall::{get_syscall_declaration, get_syscall_id, get_syscall_name, SyscallDeclaration},
    },
};

const UNKNOWN_SYSCALL_ID: u16 = 1337;
const OPEN_TREE_SYSCALL_ID: u16 = 428;

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetAPIVersion() -> u64 {
    1
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let mut syscall_id: u16 = UNKNOWN_SYSCALL_ID;
    let mut syscall_name = String::new();
    match get_syscall_name(syscall_id) {
        Ok(name) => {
            syscall_name = name;
        }
        Err(e) => {
            errorf!("{}", e);
            return 1;
        }
    }

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
    match get_syscall_name(syscall_id) {
        Ok(name) => {
            syscall_name = name;
        }
        Err(e) => {
            errorf!("{}", e);
            return 1;
        }
    }

    // open_tree has the same ID for both amd64 and arm64.
    syscall_name = "open_tree".to_string();
    let mut id = 0;
    match get_syscall_id(syscall_name.clone()) {
        Ok(val) => {
            id = val;
        }
        Err(e) => {
            errorf!("{}", e);
            return 1;
        }
    }

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
    match get_syscall_id(syscall_name.clone()) {
        Ok(val) => {
            errorf!(
                "expected no syscall ID for syscall {}, got {}",
                syscall_name,
                val
            );
            return 1;
        }
        Err(_) => {}
    }

    match get_syscall_declaration(&syscall_name) {
        Ok(val) => {
            errorf!(
                "expected no declaration for syscall {}, but got {:?}",
                syscall_name,
                val
            );
            return 1;
        }
        Err(_) => {}
    }

    let declaration: SyscallDeclaration;

    let syscall_name = "execve".to_string();
    match get_syscall_declaration(&syscall_name) {
        Ok(val) => {
            declaration = val;
        }
        Err(e) => {
            errorf!("{}", e);
            return 1;
        }
    }

    let size = std::mem::size_of_val(&declaration);
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

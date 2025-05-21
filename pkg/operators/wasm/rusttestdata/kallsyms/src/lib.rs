use api::errorf;
use api::ig::{kallsyms, log::LogLevel};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetAPIVersion() -> u64 {
    1
}

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

use api::ig::datasources::FieldKind;
const INVALID_PTR: u32 = 17 * 1024 * 1024;

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetAPIVersion() -> u64 {
    1
}

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

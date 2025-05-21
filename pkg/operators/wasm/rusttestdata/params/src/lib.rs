use api::{
    errorf,
    ig::{log::LogLevel, params::get_param_value},
};

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
pub fn gadgetStart() -> i32 {
    let mut val = String::new();
    match get_param_value("param-key".to_string(), 32) {
        Ok(value) => {
            val = value;
        }
        Err(e) => {
            errorf!("failed to get param: {:?}", e);
            return 1;
        }
    }

    let expected = "param-value".to_string();
    if val != expected {
        errorf!("param value should be {:?}, got: {:?}", expected, val);
        return 1;
    }

    match get_param_value("non-existing-param".to_string(), 32) {
        Ok(_) => {
            errorf!("looking for non-existing-param succeeded");
            return 1;
        }
        Err(_) => {}
    }

    0
}

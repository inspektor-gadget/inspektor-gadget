use api::{
    errorf,
    {log::LogLevel, params::get_param_value},
};

#[no_mangle]
#[allow(non_snake_case)]
pub fn gadgetStart() -> i32 {
    let Ok(val) = get_param_value("param-key".to_string(), 32) else {
        errorf!("failed to get param");
        return 1;
    };

    let expected = "param-value".to_string();
    if val != expected {
        errorf!("param value should be {:?}, got: {:?}", expected, val);
        return 1;
    }

    if let Ok(_) = get_param_value("non-existing-param".to_string(), 32) {
        errorf!("looking for non-existing-param succeeded");
        return 1;
    }

    0
}

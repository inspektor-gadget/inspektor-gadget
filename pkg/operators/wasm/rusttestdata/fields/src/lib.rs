use api::{
    datasources::{DataSource, Field, FieldKind},
    errorf,
    log::LogLevel,
};
use std::{any::Any, sync::Arc};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let Ok(ds) = DataSource::get_datasource("myds".to_string()) else {
        errorf!("failed to get datasource");
        return 1;
    };
    #[derive(Debug, Clone)]
    struct MyField {
        name: &'static str,
        typ: FieldKind,
        acc: Field,
        val: Arc<dyn Any + Send + Sync>,
        tag: &'static str,
    }

    let mut fields = vec![
        MyField {
            name: "field_bool",
            typ: FieldKind::Bool,
            val: Arc::new(true),
            tag: "tag_bool",
            acc: Field(0),
        },
        MyField {
            name: "field_int8",
            typ: FieldKind::Int8,
            val: Arc::new(-123i8),
            tag: "tag_int8",
            acc: Field(0),
        },
        MyField {
            name: "field_int16",
            typ: FieldKind::Int16,
            val: Arc::new(-25647i16),
            tag: "tag_int16",
            acc: Field(0),
        },
        MyField {
            name: "field_int32",
            typ: FieldKind::Int32,
            val: Arc::new(-535245564i32),
            tag: "tag_int32",
            acc: Field(0),
        },
        MyField {
            name: "field_int64",
            typ: FieldKind::Int64,
            val: Arc::new(-1234567890i64),
            tag: "tag_int64",
            acc: Field(0),
        },
        MyField {
            name: "field_uint8",
            typ: FieldKind::Uint8,
            val: Arc::new(56u8),
            tag: "tag_uint8",
            acc: Field(0),
        },
        MyField {
            name: "field_uint16",
            typ: FieldKind::Uint16,
            val: Arc::new(12345u16),
            tag: "tag_uint16",
            acc: Field(0),
        },
        MyField {
            name: "field_uint32",
            typ: FieldKind::Uint32,
            val: Arc::new(1234567890u32),
            tag: "tag_uint32",
            acc: Field(0),
        },
        MyField {
            name: "field_uint64",
            typ: FieldKind::Uint64,
            val: Arc::new(1234567890123456u64),
            tag: "tag_uint64",
            acc: Field(0),
        },
        MyField {
            name: "field_float32",
            typ: FieldKind::Float32,
            val: Arc::new(3.14159f32),
            tag: "tag_float32",
            acc: Field(0),
        },
        MyField {
            name: "field_float64",
            typ: FieldKind::Float64,
            val: Arc::new(3.14159265359f64),
            tag: "tag_float64",
            acc: Field(0),
        },
        MyField {
            name: "field_string",
            typ: FieldKind::String,
            val: Arc::new("Hello, World!".to_string()),
            tag: "tag_string",
            acc: Field(0),
        },
        MyField {
            name: "field_bytes",
            typ: FieldKind::Bytes,
            val: Arc::new(vec![0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x5u8]),
            tag: "tag_bytes",
            acc: Field(0),
        },
    ];

    for f in fields.iter_mut() {
        let Ok(field) = ds.add_field(f.name, f.typ) else {
            let name = f.name;
            errorf!("failed to add field: {}", name);
            return 1;
        };
        if let Err(e) = field.add_tag(f.tag) {
            let tag = f.tag;
            errorf!("failed to add tag: {} -> {:?}", tag, e);
            return 1;
        }
        f.acc = field;
    }

    let Ok(host_field) = ds.get_field("host_field") else {
        errorf!("failed to get host field");
        return 1;
    };

    fields.push(MyField {
        name: "host_field",
        typ: FieldKind::String,
        val: Arc::new("LOCALHOST".to_string()),
        tag: "host_tag",
        acc: host_field,
    });

    let result = ds.subscribe(
        {
            move |_source, data| {
                for f in fields.iter() {
                    let field = f.acc;

                    if let Err(e) = field.set_data(data, &*f.val) {
                        let name = f.name;
                        errorf!("failed to set field {}: {:?}", name, e);
                        panic!("failed to set field");
                    }
                }
            }
        },
        0,
    );

    if result.is_err() {
        errorf!("failed to subscribe");
        return 1;
    }

    0
}

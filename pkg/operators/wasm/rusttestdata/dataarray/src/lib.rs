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
    datasources::{DataArray, DataSource, FieldKind},
    fields::FieldData,
    log::LogLevel,
    warnf,
};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let Ok(ds) = DataSource::get_datasource("myds".to_string()) else {
        warnf!("failed to get datasource");
        return 1;
    };

    let Ok(foo_field) = ds.get_field("foo") else {
        warnf!("failed to get host field");
        return 1;
    };

    let Err(err) = ds.subscribe_array(
        move |_source: DataSource, mut array: DataArray| {
            let len = array.len();
            if len != 10 {
                warnf!("bad length: got: {}, expected: 10", len);
                panic!("bad length");
            }

            // Update value of first 10 elements
            for i in 0..10 {
                let data = array.get(i);
                let Ok(FieldData::Uint32(val)) = foo_field.get_data(data, FieldKind::Uint32) else {
                    warnf!("failed to get field at index {}", i);
                    panic!("failed to get field");
                };

                if let Err(e) = foo_field.set_data(data, &(val * i as u32)) {
                    warnf!("failed to set field: {:?}", e);
                }
            }

            // Add 5 additional elements
            for i in 10..15 {
                let data = array.new();
                if let Err(e) = foo_field.set_data(data, &(424143 * i as u32)) {
                    warnf!("failed to set field: {:?}", e);
                }
                array.append(data).expect("failed to append data");
            }

            Ok(())
        },
        0,
    ) else {
        return 0;
    };

    warnf!("failed to subscribe {:?}", err);
    1
}

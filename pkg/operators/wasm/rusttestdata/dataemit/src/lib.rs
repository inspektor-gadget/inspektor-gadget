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
    {
        datasources::{ Data, DataSource, DataSourceType, FieldKind, Packet },
        fields::FieldData,
        log::LogLevel,
    },
};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let old_ds_name = "old_ds".to_string();
    let old_ds = match DataSource::get_datasource(old_ds_name) {
        Ok(_old_ds) => _old_ds,
        Err(err) => {
            errorf!("getting datasource"/*, old_ds_name*//*, err*/);
            return 1;
        }
    };

    let foo_field_name = "foo";
    let foo_field = match old_ds.get_field(foo_field_name) {
        Ok(_foo_field) => _foo_field,
        Err(err) => {
            errorf!("getting field {}", foo_field_name/*, err*/);
            return 1;
        }
    };

    let new_ds_name = "new_ds".to_string();
    let new_ds = match DataSource::new_datasource(new_ds_name, DataSourceType::Single) {
        Ok(_new_ds) => _new_ds,
        Err(err) => {
            errorf!("creating datasource"/*, new_ds_name*//*, err*/);
            return 1;
        }
    };

    let bar_field_name = "bar";
    let bar_field = match new_ds.add_field(bar_field_name, FieldKind::Uint32) {
        Ok(_bar_field) => _bar_field,
        Err(err) => {
            errorf!("adding field {}", bar_field_name/*, err*/);
            return 1;
        }
    };

    if let Err(err) = old_ds.subscribe(move |_source: DataSource, data: Data| {
        let val_data = match foo_field.get_data(data, FieldKind::Uint32) {
            Ok(_val_data) => _val_data,
            Err(err) => {
                panic!("getting field {}: {}", foo_field_name, err);
            },
        };

        let val = match val_data {
            FieldData::Uint32(_val_data) => _val_data,
            _ => panic!("field has wrong type"),
        };

        if val % 2 != 0 {
            return;
        }

        let packet = match new_ds.new_packet_single() {
            Ok(_packet) => _packet,
            Err(err) => {
                panic!("creating new packet"/*, err*/);
            },
        };

        if let Err(_) = bar_field.set_data(Data(packet.0), &(val * 5)) {
            panic!("setting field");
        }

        if let Err(_) = new_ds.emit_and_release(Packet(packet.0)) {
            panic!("emitting packet");
        }
    }, 0) {
        errorf!("subscribing"/*, old_ds_name*//*, err*/);
        return 1;
    }

    0
}

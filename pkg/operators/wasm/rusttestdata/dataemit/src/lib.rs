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
    datasources::{Data, DataSource, DataSourceType, FieldKind, Packet},
    fields::FieldData,
    log::LogLevel,
    warnf,
};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let Ok(old_ds) = DataSource::get_datasource("old_ds".to_string()) else {
        warnf!("failed to get datasource");
        return 1;
    };

    let foo_field = match old_ds.get_field("foo") {
        Ok(field) => field,
        Err(e) => {
            warnf!("failed to get host field: {:?}", e);
            return 1;
        }
    };

    let Ok(new_ds) = DataSource::new_datasource("new_ds".to_string(), DataSourceType::Single)
    else {
        warnf!("failed to create datasource");
        return 1;
    };

    let bar_field = match new_ds.add_field("bar", FieldKind::Uint32) {
        Ok(field) => field,
        Err(e) => {
            warnf!("failed to add field: {:?}", e);
            return 1;
        }
    };

    let Err(e) = old_ds.subscribe(
        move |_source: DataSource, data: Data| {
            let val = match foo_field.get_data(data, FieldKind::Uint32) {
                Ok(FieldData::Uint32(v)) => v,
                Err(e) => {
                    warnf!("failed to get field: {:?}", e);
                    panic!("failed to get field");
                }
                _ => {
                    warnf!("unexpected field data type");
                    panic!("unexpected field data type");
                }
            };

            if val % 2 == 0 {
                let packet = match new_ds.new_packet_single() {
                    Ok(p) => p,
                    Err(e) => {
                        warnf!("failed to create new packet: {:?}", e);
                        panic!("failed to create packet");
                    }
                };
                _ = bar_field.set_data(Data(packet.0), &(val * 5));
                _ = new_ds.emit_and_release(Packet(packet.0));
            }
        },
        0,
    ) else {
        return 0;
    };

    warnf!("failed to subscribe: {:?}", e);
    1
}

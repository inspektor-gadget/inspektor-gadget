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

use api::errorf;
use api::ig::{
    log::LogLevel,
    map::{Map, MapSpec, MapType},
};

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MapTestStruct {
    a: i32,
    b: i32,
    c: i8,
    _pad: [i8; 3],
}

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
fn gadgetStart() -> i32 {
    let map_of_map_name = "map_of_map";
    let mut inner_map: Map = Map(0);
    let key = MapTestStruct {
        a: 42,
        b: 42,
        c: 43,
        _pad: [0; 3],
    };

    let map_of_map = match Map::get(map_of_map_name) {
        Ok(map) => map,
        Err(_) => {
            errorf!("{} map must exist", map_of_map_name);
            return 1;
        }
    };
    let hash_map_name = "test_hash".to_string();

    let inner_map_spec = MapSpec {
        name: hash_map_name.clone(),
        map_type: MapType::Hash,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    };

    let hash_map = match Map::new(inner_map_spec.clone()) {
        Ok(map) => map,
        Err(_) => {
            errorf!("creating map {}", hash_map_name);
            return 1;
        }
    };

    if let Err(e) = map_of_map.put(&key, &hash_map) {
        errorf!(
            "setting {} inner map value for key {:?} in {}: {}",
            hash_map_name,
            key,
            map_of_map_name,
            e
        );
        return 1;
    }
    match map_of_map.lookup(&key, &mut inner_map) {
        Ok(_) => {}
        Err(_) => {
            errorf!("no value found for key {:?} in {}", key, map_of_map_name);
            return 1;
        }
    };

    if inner_map.0 == 0 {
        errorf!("expected handle to be different than 0");
        return 1;
    }

    if inner_map.0 == hash_map.0 {
        errorf!("expected handle to be different than hashMap");
        return 1;
    }

    let k: u32 = 42;
    let v: u32 = 43;
    if let Err(e) = inner_map.put(&k, &v) {
        errorf!("putting value in inner map {}: {}", hash_map_name, e);
        return 1;
    }

    if let Err(_) = map_of_map.delete(&key) {
        errorf!("deleting map {:?}", hash_map);
        return 1;
    }

    0
}

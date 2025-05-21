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
    ig::{
        log::LogLevel,
        map::{Map, MapSpec, MapType, MapUpdateFlags},
    },
};
#[no_mangle]
#[allow(non_snake_case)]
fn gadgetAPIVersion() -> u64 {
    1
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let map_name = "test_map";
    let map = Map::get(map_name);
    match map {
        Ok(_) => {
            api::errorf!("{} map does not exist", map_name);
            1
        }
        Err(_) => 0,
    }
}

// #[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MapTestStruct {
    a: i32,
    b: i32,
    c: i8,
    _pad: [i8; 3],
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetStart() -> i32 {
    let map_name = "test_map";
    let mut expected_val: i32 = 42;
    let new_val: i32 = 43;
    let key = MapTestStruct {
        a: 42,
        b: 42,
        c: 43,
        _pad: [0; 3],
    };
    let mut val: i32 = 0;
    //Defining m inside a block to test Map drop trait.
    {
        let m = match Map::get(map_name) {
            Ok(map) => map,
            Err(err) => {
                errorf!("map doesn't exists: {}", err);
                return 1;
            }
        };

        let _res = match m.put(&key, &expected_val) {
            Ok(_) => {}
            Err(err) => {
                api::errorf!(
                    "setting {} value for {:?} key in {}: {}",
                    expected_val,
                    key,
                    map_name,
                    err
                );
                return 1;
            }
        };

        match m.lookup(&key, &mut val) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!("no value found for key {:?} in {}", key, map_name);
                return 1;
            }
        }

        if val != expected_val {
            api::errorf!("expected value {}, got {}", expected_val, val);
            return 1;
        }

        //     Code is not required as parameter's type are checked at compile time
        //     match m.lookup(&key, val) {
        //     Ok(_) => {api::error!("lookup only accepts pointer for value argument");
        //             return 1;},
        //     Err(_) => {
        //     }
        // }

        match m.update(&key, &new_val, MapUpdateFlags::UpdateExist) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!("updating value for key {:?} in {}", key, map_name);
                return 1;
            }
        }

        match m.lookup(&key, &mut val) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!("no value found for key {:?} in {}", key, map_name);
                return 1;
            }
        }
        if val != new_val {
            api::errorf!("expected value {}, got {}", new_val, val);
            return 1;
        }

        match m.delete(&key) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!("deleting value for key {:?} in {}", key, map_name);
                return 1;
            }
        }
        match m.put(&key, &val) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!("setting {} value for key {:?} in {:?}", val, key, map_name);
                return 1;
            }
        }

        match m.update(&key, &new_val, MapUpdateFlags::UpdateNoExist) {
            Ok(_) => {
                api::errorf!(
                    "cannot update value for key {:?} in {} as it is not already present",
                    key,
                    map_name
                );
                return 1;
            }
            Err(_) => {}
        }

        match m.update(&key, &new_val, MapUpdateFlags::UpdateExist) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!(
                    "cannot update value for key {:?} in {} as it is already present",
                    key,
                    map_name
                );
                return 1;
            }
        };
        match m.delete(&key) {
            Ok(_) => {}
            Err(_) => {
                api::errorf!("deleting value for key {:?} in {}", key, map_name);
                return 1;
            }
        };

        match m.delete(&key) {
            Ok(_) => {
                api::errorf!("there is value for key {:?} in {}", key, map_name);
                return 1;
            }
            Err(_) => {}
        }
    }
    // As the block ends, the map tries to be dropped, but cannot close map got with get()

    let map_spec = MapSpec {
        name: "map_test".to_string(),
        map_type: MapType::Hash,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    };

    let new_map = match Map::new(map_spec.clone()) {
        Ok(map) => map,
        Err(_) => {
            let name = map_spec.name.clone();
            api::errorf!("creating map {:?}", name);
            return 1;
        }
    };

    let k: i32 = 42;
    val = 43;
    match new_map.put(&k, &val) {
        Ok(_) => {}
        Err(_) => {
            let name = map_spec.name.clone();
            api::errorf!("setting {} value for key {} in {:?}", val, k, name);
            return 1;
        }
    }

    match new_map.lookup(&k, &mut val) {
        Ok(_) => {}
        Err(_) => {
            let name = map_spec.name.clone();
            api::errorf!("no value found for key {} in {:?}", k, name);
            return 1;
        }
    }

    expected_val = 43;
    if val != expected_val {
        api::errorf!("expected value {}, got {}", expected_val, val);
        return 1;
    }

    let k2 = 0xdead;
    val = 0xcafe;
    match new_map.put(&k2, &val) {
        Ok(_) => {
            let name = map_spec.name.clone();
            api::errorf!("map {:?} has one max entry, trying to put two", name);
            return 1;
        }
        Err(_) => {}
    }

    0
}

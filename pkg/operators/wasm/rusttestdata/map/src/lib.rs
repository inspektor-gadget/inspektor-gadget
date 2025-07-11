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
    map::{Map, MapSpec, MapType, MapUpdateFlags},
};

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
    let map_name = "test_map";
    if let Ok(_) = Map::get(map_name) {
        api::errorf!("{} map does not exist", map_name);
        return 1;
    }
    0
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
        let Ok(m) = Map::get(map_name) else {
            errorf!("map doesn't exists: {}", map_name);
            return 1;
        };

        if let Err(err) = m.put(&key, &expected_val) {
            api::errorf!(
                "setting {} value for {:?} key in {}: {}",
                expected_val,
                key,
                map_name,
                err
            );
            return 1;
        }

        if let Err(_) = m.lookup(&key, &mut val) {
            api::errorf!("no value found for key {:?} in {}", key, map_name);
            return 1;
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

        if let Err(_) = m.update(&key, &new_val, MapUpdateFlags::UpdateExist) {
            api::errorf!("updating value for key {:?} in {}", key, map_name);
            return 1;
        }

        if let Err(_) = m.lookup(&key, &mut val) {
            api::errorf!("no value found for key {:?} in {}", key, map_name);
            return 1;
        }
        if val != new_val {
            api::errorf!("expected value {}, got {}", new_val, val);
            return 1;
        }

        if let Err(_) = m.delete(&key) {
            api::errorf!("deleting value for key {:?} in {}", key, map_name);
            return 1;
        }

        if let Err(_) = m.put(&key, &val) {
            api::errorf!("setting {} value for key {:?} in {:?}", val, key, map_name);
            return 1;
        }

        if let Ok(_) = m.update(&key, &new_val, MapUpdateFlags::UpdateNoExist) {
            api::errorf!(
                "cannot update value for key {:?} in {} as it is not already present",
                key,
                map_name
            );
            return 1;
        }

        if let Err(_) = m.update(&key, &new_val, MapUpdateFlags::UpdateExist) {
            api::errorf!(
                "cannot update value for key {:?} in {} as it is already present",
                key,
                map_name
            );
            return 1;
        }
        if let Err(_) = m.delete(&key) {
            api::errorf!("deleting value for key {:?} in {}", key, map_name);
            return 1;
        }

        if let Ok(_) = m.delete(&key) {
            api::errorf!("there is value for key {:?} in {}", key, map_name);
            return 1;
        }
    }
    // As the block ends, the map tries to be dropped, but cannot close map got with get()

    let map_spec = MapSpec {
        name: "map_test".to_string(),
        typ: MapType::Hash,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    };

    let Ok(new_map) = Map::new(&map_spec) else {
        api::errorf!("creating map {:?}", &map_spec.name);
        return 1;
    };

    let k: i32 = 42;
    val = 43;
    if let Err(_) = new_map.put(&k, &val) {
        api::errorf!("setting {} value for key {} in {:?}", val, k, &map_spec.name);
        return 1;
    }

    if let Err(_) = new_map.lookup(&k, &mut val) {
        api::errorf!("no value found for key {} in {:?}", k, &map_spec.name);
        return 1;
    }

    expected_val = 43;
    if val != expected_val {
        api::errorf!("expected value {}, got {}", expected_val, val);
        return 1;
    }

    let k2 = 0xdead;
    val = 0xcafe;
    if let Ok(_) = new_map.put(&k2, &val) {
        api::errorf!("map {:?} has one max entry, trying to put two", &map_spec.name);
        return 1;
    }

    0
}

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

use crate::rust_bindings::helpers::{any_to_buf_ptr, string_to_buf_ptr};

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "newMap"]
    fn new_map(name: u64, typ: u32, key_size: u32, value_size: u32, max_entries: u32) -> u32;
    #[link_name = "getMap"]
    fn get_map(name: u64) -> u32;
    #[link_name = "mapLookup"]
    fn map_lookup(map: u32, key_ptr: u64, value_ptr: u64) -> u32;
    #[link_name = "mapUpdate"]
    fn map_update(map: u32, key_ptr: u64, value_ptr: u64, flags: u64) -> u32;
    #[link_name = "mapDelete"]
    fn map_delete(map: u32, key_ptr: u64) -> u32;
    #[link_name = "mapRelease"]
    fn map_release(map: u32) -> u32;
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MapType {
    Unspecified = 0,
    Hash,
    Array,
    ProgramArray,
    PerfEventArray,
    PerCPUHash,
    PerCPUArray,
    StackTrace,
    CGroupArray,
    LRUHash,
    LRUCPUHash,
    LPMTrie,
    ArrayOfMaps,
    HashOfMaps,
    DevMap,
    SockMap,
    CPUMap,
    XSKMap,
    SockHash,
    CGroupStorage,
    ReusePortSockArray,
    PerCPUCGroupStorage,
    Queue,
    Stack,
    SkStorage,
    DevMapHash,
    StructOpsMap,
    RingBuf,
    InodeStorage,
    TaskStorage,
    BloomFilter,
    UserRingbuf,
    CgroupStorage,
    Arena,
}

pub type Result<T> = std::result::Result<T, MapError>;

pub enum MapError {
    ErrCreateMap(String),
    ErrNotFound(String),
    ErrLookup(String),
    ErrUpdateMap(String),
}

#[repr(u64)]
#[derive(Clone, Copy)]
pub enum MapUpdateFlags {
    UpdateAny = 0,
    UpdateNoExist = 1,
    UpdateExist = 2,
    UpdateLock = 4,
}

pub struct Map(pub u32);

pub struct MapSpec {
    name: String,
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

impl Map {
    pub fn new(spec: MapSpec) -> Result<Self> {
        let name_ptr = string_to_buf_ptr(&spec.name);
        let ret = unsafe {
            new_map(
                name_ptr,
                spec.map_type as u32,
                spec.key_size,
                spec.value_size,
                spec.max_entries,
            )
        };
        if ret == 0 {
            return Err(MapError::ErrCreateMap(String::from(format!(
                "Failed to create map {}",
                spec.name
            ))));
        }
        Ok(Map(ret))
    }

    pub fn get(name: &str) -> Result<Self> {
        let ret = unsafe { get_map(string_to_buf_ptr(name)) };
        if ret == 0 {
            return Err(MapError::ErrNotFound(String::from(format!(
                "Map {} not found",
                name
            ))));
        }
        Ok(Map(ret))
    }
    // Only allows pointers to key and value
    pub fn lookup<T: Copy, Clone>(&self, key: T, value: T) -> Result<()> {
        let key_ptr = any_to_buf_ptr(&key).expect("Invalid key type");
        let val_ptr = any_to_buf_ptr(&value).expect("Invalid value type");

        let ret = unsafe { map_lookup(self.0, key_ptr, val_ptr) };
        if ret != 0 {
            return Err(MapError::ErrLookup(String::from("Error looking up map")));
        }
        Ok(())
    }

    pub fn put<T>(&self, key: &T, value: &T) -> Result<()> {
        return self.update(key, value, MapUpdateFlags::UpdateAny);
    }

    fn update<T>(&self, key: &T, value: &T, flags: MapUpdateFlags) -> Result<()> {
        let key_ptr = any_to_buf_ptr(&key).expect("Invalid key type");
        let val_ptr = any_to_buf_ptr(&value).expect("Invalid value type");
        let ret = unsafe { map_update(self.0, key_ptr, val_ptr, flags as u64) };
        if ret != 0 {
            return Err(MapError::ErrUpdateMap(String::from("Failed to update map")));
        }
        Ok(())
    }

    pub fn delete<T: Copy>(&self, key: &T) -> Result<()> {
        let key_ptr = any_to_buf_ptr(&key).expect("Invalid key type");
        let ret = unsafe { map_delete(self.0, key_ptr) };
        if ret != 0 {
            return Err(MapError::ErrUpdateMap(String::from("Failed to delete key")));
        }
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let ret = unsafe { map_release(self.0) };
        if ret != 0 {
            return Err(MapError::ErrUpdateMap(String::from("Failed to close map")));
        }
        Ok(())
    }
}

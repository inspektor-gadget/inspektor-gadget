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

use crate::{
    error,
    ig::helpers::{any_to_buf_ptr, string_to_buf_ptr},
};

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "newMap"]
    fn _new(name: u64, typ: u32, key_size: u32, value_size: u32, max_entries: u32) -> u32;
    #[link_name = "getMap"]
    fn _get(name: u64) -> u32;
    #[link_name = "mapLookup"]
    fn _lookup(map: u32, key_ptr: u64, value_ptr: u64) -> u32;
    #[link_name = "mapUpdate"]
    fn _update(map: u32, key_ptr: u64, value_ptr: u64, flags: u64) -> u32;
    #[link_name = "mapDelete"]
    fn _delete(map: u32, key_ptr: u64) -> u32;
    #[link_name = "mapRelease"]
    fn _release(map: u32) -> u32;
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

pub type Result<T> = std::result::Result<T, String>;

#[repr(u64)]
#[derive(Clone, Copy)]
pub enum MapUpdateFlags {
    UpdateAny = 0,
    UpdateNoExist = 1,
    UpdateExist = 2,
    UpdateLock = 4,
}

#[derive(Debug)]
pub struct Map(pub u32);

#[derive(Clone)]
pub struct MapSpec {
    pub name: String,
    pub map_type: MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl Drop for Map {
    fn drop(&mut self) {
        let ret = unsafe { _release(self.0) };
        if ret != 0 {
            error!("Failed to release map");
        }
    }
}

impl Map {
    pub fn new(spec: MapSpec) -> Result<Self> {
        let name_ptr = string_to_buf_ptr(&spec.name);
        let ret = unsafe {
            _new(
                name_ptr,
                spec.map_type as u32,
                spec.key_size,
                spec.value_size,
                spec.max_entries,
            )
        };
        if ret == 0 {
            Err(format!("Failed to create map {}", spec.name))
        } else {
            Ok(Map(ret))
        }
    }

    pub fn get(name: &str) -> Result<Self> {
        let ret = unsafe { _get(string_to_buf_ptr(name)) };
        if ret == 0 {
            Err(format!("Map {} not found", name))
        } else {
            Ok(Map(ret))
        }
    }
    // Only allows pointers to key and value
    pub fn lookup<T, U>(&self, key: &T, value: &mut U) -> Result<()> {
        let key_ptr = any_to_buf_ptr(key).expect("Invalid key type");
        let value_ptr = any_to_buf_ptr(value).expect("Invalid value type");

        let ret = unsafe { _lookup(self.0, key_ptr, value_ptr) };
        if ret != 0 {
            return Err(String::from("Error looking up map"));
        }
        let val_len = (value_ptr >> 32) as usize;
        let bytes = unsafe { std::slice::from_raw_parts(value_ptr as *const u8, val_len) };
        unsafe {
            std::ptr::copy(bytes.as_ptr(), value as *mut U as *mut u8, val_len);
        }
        Ok(())
    }

    pub fn put<T, U>(&self, key: &T, value: &U) -> Result<()> {
        self.update(key, value, MapUpdateFlags::UpdateAny)
    }

    pub fn update<T, U>(&self, key: &T, value: &U, flags: MapUpdateFlags) -> Result<()> {
        let key_ptr = match any_to_buf_ptr(key) {
            Ok(ptr) => ptr,
            Err(err) => return Err(err),
        };

        let value_ptr = match any_to_buf_ptr(value) {
            Ok(ptr) => ptr,
            Err(err) => return Err(err),
        };
        let ret = unsafe { _update(self.0, key_ptr, value_ptr, flags as u64) };
        if ret != 0 {
            return Err(String::from("Failed to update map"));
        }
        Ok(())
    }

    pub fn delete<T>(&self, key: &T) -> Result<()> {
        let key_ptr = match any_to_buf_ptr(key) {
            Ok(ptr) => ptr,
            Err(err) => return Err(err),
        };
        let ret = unsafe { _delete(self.0, key_ptr) };
        if ret != 0 {
            return Err(String::from("Failed to delete key"));
        }
        Ok(())
    }
}

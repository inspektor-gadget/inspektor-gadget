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
    helpers::{any_to_buf_ptr, string_to_buf_ptr},
};

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "newMap"]
    fn _map_new(name: u64, typ: u32, key_size: u32, value_size: u32, max_entries: u32) -> u32;
    #[link_name = "getMap"]
    fn _map_get(name: u64) -> u32;
    #[link_name = "mapLookup"]
    fn _map_lookup(map: u32, key_ptr: u64, value_ptr: u64) -> u32;
    #[link_name = "mapUpdate"]
    fn _map_update(map: u32, key_ptr: u64, value_ptr: u64, flags: u64) -> u32;
    #[link_name = "mapDelete"]
    fn _map_delete(map: u32, key_ptr: u64) -> u32;
    #[link_name = "mapRelease"]
    fn _map_release(map: u32) -> u32;
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

#[derive(Debug, Default)]
pub struct Map {
    pub handle: u32,
    created: bool,
}

#[derive(Clone)]
pub struct MapSpec {
    pub name: String,
    pub typ: MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl Drop for Map {
    fn drop(&mut self) {
        if !self.created {
            return;
        }

        let ret = unsafe { _map_release(self.handle) };
        if ret != 0 {
            error!("Failed to release map");
        }
    }
}

impl Map {
    pub fn new(spec: &MapSpec) -> Result<Self> {
        let name_ptr = string_to_buf_ptr(&spec.name);
        let ret = unsafe {
            _map_new(
                name_ptr.0,
                spec.typ as u32,
                spec.key_size,
                spec.value_size,
                spec.max_entries,
            )
        };
        if ret == 0 {
            Err(format!("Failed to create map {}", spec.name))
        } else {
            Ok(Map{ handle: ret, created: true })
        }
    }

    pub fn get(name: &str) -> Result<Self> {
        let ret = unsafe { _map_get(string_to_buf_ptr(name).0) };
        if ret == 0 {
            Err(format!("Map {} not found", name))
        } else {
            Ok(Map{ handle: ret, created: false })
        }
    }
    // Only allows pointers to key and value
    pub fn lookup<T, U>(&self, key: &T, value: &mut U) -> Result<()> {
        let key_ptr = any_to_buf_ptr(key)?;
        let value_ptr = any_to_buf_ptr(value)?;

        let ret = unsafe { _map_lookup(self.handle, key_ptr.0, value_ptr.0) };
        if ret != 0 {
            return Err(String::from("Error looking up map"));
        }
        let val_len = value_ptr.0 >> 32;
        if let Some(bytes) = value_ptr.bytes() {
            unsafe {
                std::ptr::copy(bytes.as_ptr(), value as *mut U as *mut u8, val_len as usize);
            }
        };
        Ok(())
    }

    pub fn put<T, U>(&self, key: &T, value: &U) -> Result<()> {
        self.update(key, value, MapUpdateFlags::UpdateAny)
    }

    pub fn update<T, U>(&self, key: &T, value: &U, flags: MapUpdateFlags) -> Result<()> {
        let key_ptr = any_to_buf_ptr(key)?;
        let value_ptr = any_to_buf_ptr(value)?;

        let ret = unsafe { _map_update(self.handle, key_ptr.0, value_ptr.0, flags as u64) };
        if ret != 0 {
            return Err(String::from("Failed to update map"));
        }
        Ok(())
    }

    pub fn delete<T>(&self, key: &T) -> Result<()> {
        let key_ptr = any_to_buf_ptr(key)?;
        let ret = unsafe { _map_delete(self.handle, key_ptr.0) };
        if ret != 0 {
            return Err(String::from("Failed to delete key"));
        }
        Ok(())
    }
}

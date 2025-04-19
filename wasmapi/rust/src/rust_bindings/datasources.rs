// Copyright 2024 The Inspektor Gadget authors
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

use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use crate::rust_bindings::helpers::string_to_buf_ptr; //relative paths may hinder in testing.

#[derive(Debug)]
pub enum DataSourceError {
    NotFound(String),
    CreationFailed(String),
    SubscribingFailed,
    PacketCreationFailed,
    EmitFailed,
    ReleaseFailed,
    UnreferenceFailed,
    AddFieldFailed(String),
    AppendFailed,
    GeneralError,
}

pub type Result<T> = std::result::Result<T, DataSourceError>;

#[repr(u32)] // Specifies the enums to be casted as u32, similar to C enums.
#[derive(Clone, Copy)]
pub enum SubscriptionType {
    Invalid = 0,
    Data = 1,
    Array = 2,
    Packet = 3,
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum DataSourceType {
    Undefined = 0,
    Single = 1,
    Array = 2,
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum FieldKind {
    Invalid = 0,
    Bool = 1,
    Int8 = 2,
    Int16 = 3,
    Int32 = 4,
    Int64 = 5,
    Uint8 = 6,
    Uint16 = 7,
    Uint32 = 8,
    Uint64 = 9,
    Float32 = 10,
    Float64 = 11,
    String = 12,
    CString = 13,
    Bytes = 14,
}

pub enum CallBack {
    Data(DataFunc),
    Array(ArrayFunc),
    Packet(PacketFunc),
}

type DataFunc = fn(DataSource, Data);
type ArrayFunc = fn(DataSource, DataArray) -> Result<()>;
type PacketFunc = fn(DataSource, Packet) -> Result<()>;

extern "C" {
    #[link_name = "newDataSource"]
    fn new_data_source(name: u64, typ: u32) -> u32;

    #[link_name = "getDataSource"]
    fn get_data_source(name: u64) -> u32;

    #[link_name = "dataSourceSubscribe"]
    fn datasource_subscribe(ds: u32, typ: u32, prio: u32, cb: u64) -> u32;

    #[link_name = "dataSourceGetField"]
    fn data_source_get_field(ds: u32, name: u64) -> u32;

    #[link_name = "dataSourceAddField"]
    fn data_source_add_field(ds: u32, name: u64, kind: u32) -> u32;

    #[link_name = "dataSourceNewPacketSingle"]
    fn data_source_new_packet_single(ds: u32) -> u32;

    #[link_name = "dataSourceNewPacketArray"]
    fn data_source_new_packet_array(ds: u32) -> u32;

    #[link_name = "dataSourceEmitAndRelease"]
    fn data_source_emit_and_release(ds: u32, packet: u32) -> u32;

    #[link_name = "dataSourceRelease"]
    fn data_source_release(ds: u32, packet: u32) -> u32;

    #[link_name = "dataSourceUnreference"]
    fn data_source_unreference(ds: u32) -> u32;

    #[link_name = "dataSourceIsReferenced"]
    fn data_source_is_referenced(ds: u32) -> u32;

    #[link_name = "dataArrayNew"]
    fn data_array_new(d: u32) -> u32;

    #[link_name = "dataArrayAppend"]
    fn data_array_append(d: u32, data: u32) -> u32;

    #[link_name = "dataArrayRelease"]
    fn data_array_release(d: u32, data: u32) -> u32;

    #[link_name = "dataArrayLen"]
    fn data_array_len(d: u32) -> u32;

    #[link_name = "dataArrayGet"]
    fn data_array_get(d: u32, index: u32) -> u32;
}

pub struct subscription {
    typ: SubscriptionType,
    cb: CallBack,
}

static DS_SUBSCRIPTION_CTR: AtomicU64 = AtomicU64::new(0);
static DS_SUBCRIPTION: Lazy<Mutex<HashMap<u64, subscription>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// lazy_static::lazy_static! {
//     static ref DS_SUBCRIPTION: Mutex<HashMap<u64, Box<dyn Fn(u32, u32) + Send>>> = Mutex::new(HashMap::new());
// }
// fn string_to_buf_ptr(s: &str) -> u64 {
//     let ptr = s.as_ptr() as u32;

//     let len = s.len() as u32;

//     (u64::from(len) << 32) | u64::from(ptr)
// }

#[derive(Clone, Copy)]
pub struct DataSource(pub u32);
#[derive(Clone, Copy)]
pub struct Packet(pub u32);
#[derive(Clone, Copy)]
pub struct Field(pub u32);
#[derive(Clone, Copy)]
pub struct Data(pub u32);
#[derive(Clone, Copy)]
pub struct DataArray(pub u32);
#[derive(Clone, Copy)]
pub struct PacketSingle(pub u32);
#[derive(Clone, Copy)]
pub struct PacketArray(pub u32);

impl DataSource {
    pub fn create_new_datasource(name: String, typ: DataSourceType) -> Result<Self> {
        let ptr = string_to_buf_ptr(name.as_str());
        let handle = unsafe { new_data_source(ptr, typ as u32) };

        if handle == 0 {
            return Err(DataSourceError::CreationFailed(name.into()));
        }
        Ok(Self(handle))
    }

    pub fn get_created_datasource(name: String) -> Result<Self> {
        let ptr = string_to_buf_ptr(name.as_str());
        let handle = unsafe { get_data_source(ptr) };
        if handle == 0 {
            return Err(DataSourceError::NotFound(name.into()));
        }
        Ok(Self(handle))
    }

    fn subscribe(&self, typ: SubscriptionType, prio: u32, cb: CallBack) -> Result<()> {
        let ctr = DS_SUBSCRIPTION_CTR.fetch_add(1, Ordering::SeqCst) + 1;
        DS_SUBCRIPTION
            .lock()
            .unwrap()
            .insert(ctr, subscription { typ, cb });
        let ret = unsafe { datasource_subscribe(self.0, typ as u32, prio, ctr) };
        if ret != 0 {
            return Err(DataSourceError::SubscribingFailed);
        }
        Ok(())
    }

    pub fn subscribe_data(&self, cb: CallBack, prio: u32) -> Result<()> {
        self.subscribe(SubscriptionType::Data, prio, cb)
    }

    pub fn subscribe_array(&self, cb: CallBack, prio: u32) -> Result<()> {
        self.subscribe(SubscriptionType::Array, prio, cb)
    }

    pub fn subscribe_packet(&self, cb: CallBack, prio: u32) -> Result<()> {
        self.subscribe(SubscriptionType::Packet, prio, cb)
    }

    pub fn get_field(&self, name: &str) -> Result<Field> {
        let ptr = string_to_buf_ptr(name);
        let ret = unsafe { data_source_get_field(self.0, ptr) };
        if ret == 0 {
            return Err(DataSourceError::NotFound(name.into()));
        }
        Ok(Field(ret))
    }

    pub fn add_field(&self, name: &str, kind: FieldKind) -> Result<Field> {
        let ptr = string_to_buf_ptr(name);
        let ret = unsafe { data_source_add_field(self.0, ptr, kind as u32) };
        if ret == 0 {
            return Err(DataSourceError::AddFieldFailed(name.into()));
        }
        Ok(Field(ret))
    }

    pub fn new_packet_single(&self) -> Result<PacketSingle> {
        let ret = unsafe { data_source_new_packet_single(self.0) };
        if ret == 0 {
            return Err(DataSourceError::PacketCreationFailed);
        }
        Ok(PacketSingle(ret))
    }

    pub fn new_packet_array(&self) -> Result<PacketArray> {
        let ret = unsafe { data_source_new_packet_array(self.0) };
        if ret == 0 {
            return Err(DataSourceError::PacketCreationFailed);
        }
        Ok(PacketArray(ret))
    }

    pub fn emit_and_release(&self, packet: Packet) -> Result<()> {
        let ret = unsafe { data_source_emit_and_release(self.0, packet.0) };
        if ret != 0 {
            return Err(DataSourceError::EmitFailed);
        }
        Ok(())
    }

    pub fn release(&self, packet: Packet) -> Result<()> {
        let ret = unsafe { data_source_release(self.0, packet.0) };
        if ret != 0 {
            return Err(DataSourceError::ReleaseFailed);
        }
        Ok(())
    }

    pub fn unreference(&self) -> Result<()> {
        let ret = unsafe { data_source_unreference(self.0) };
        if ret != 0 {
            return Err(DataSourceError::UnreferenceFailed);
        }
        Ok(())
    }

    pub fn is_referenced(&self) -> bool {
        unsafe { data_source_is_referenced(self.0) == 1 }
    }
}

impl DataArray {
    pub fn new(&self) -> Data {
        let data = unsafe { data_array_new(self.0) };
        Data(data)
    }

    pub fn append(&self, data: Data) -> Result<()> {
        let ret = unsafe { data_array_append(self.0, data.0) };
        if ret != 0 {
            return Err(DataSourceError::AppendFailed);
        }
        Ok(())
    }

    pub fn release(&self, data: Data) -> Result<()> {
        let ret = unsafe { data_array_release(self.0, data.0) };
        if ret != 0 {
            return Err(DataSourceError::ReleaseFailed);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        unsafe { data_array_len(self.0) as usize }
    }

    pub fn get(&self, index: usize) -> Data {
        let data = unsafe { data_array_get(self.0, index as u32) };
        Data(data)
    }
}

// update datasourcecallback
#[no_mangle]
pub fn dataSourceCallback(cbId: u64, ds: u32, data: u32) {
    if let Some(_val) = DS_SUBCRIPTION.lock().unwrap().get(&cbId) {
        return;
    }
    return;
}

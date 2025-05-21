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

use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crate::ig::helpers::string_to_buf_ptr; //relative paths may hinder in testing.

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
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Copy, Debug)]
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
    Array(DataArrayFunc),
    Packet(PacketFunc),
}

type DataFunc = Arc<dyn Fn(DataSource, Data) + Send + Sync + 'static>;
type DataArrayFunc = Arc<dyn Fn(DataSource, DataArray) -> Result<()> + Send + Sync + 'static>;
type PacketFunc = Arc<dyn Fn(DataSource, Packet) -> Result<()> + Send + Sync + 'static>;

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "newDataSource"]
    fn _new_datasource(name: u64, typ: u32) -> u32;

    #[link_name = "getDataSource"]
    fn _get_datasource(name: u64) -> u32;

    #[link_name = "dataSourceSubscribe"]
    fn _subscribe(ds: u32, typ: u32, prio: u32, cb: u64) -> u32;

    #[link_name = "dataSourceGetField"]
    fn _get_field(ds: u32, name: u64) -> u32;

    #[link_name = "dataSourceAddField"]
    fn _add_field(ds: u32, name: u64, kind: u32) -> u32;

    #[link_name = "dataSourceNewPacketSingle"]
    fn _new_packet_single(ds: u32) -> u32;

    #[link_name = "dataSourceNewPacketArray"]
    fn _new_packet_array(ds: u32) -> u32;

    #[link_name = "dataSourceEmitAndRelease"]
    fn _emit_and_release(ds: u32, packet: u32) -> u32;

    #[link_name = "dataSourceRelease"]
    fn _release(ds: u32, packet: u32) -> u32;

    #[link_name = "dataSourceUnreference"]
    fn _unreference(ds: u32) -> u32;

    #[link_name = "dataSourceIsReferenced"]
    fn _is_referenced(ds: u32) -> u32;

    #[link_name = "dataArrayNew"]
    fn _dataarray_new(d: u32) -> u32;

    #[link_name = "dataArrayAppend"]
    fn _dataarray_append(d: u32, data: u32) -> u32;

    #[link_name = "dataArrayRelease"]
    fn _dataarray_release(d: u32, data: u32) -> u32;

    #[link_name = "dataArrayLen"]
    fn _dataarray_len(d: u32) -> u32;

    #[link_name = "dataArrayGet"]
    fn _dataarray_get(d: u32, index: u32) -> u32;
}

pub struct Subscription {
    typ: SubscriptionType,
    cb: CallBack,
}

static DS_SUBSCRIPTION_CTR: AtomicU64 = AtomicU64::new(0);
static DS_SUBCRIPTION: Lazy<Mutex<HashMap<u64, Subscription>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Copy, Debug)]
pub struct DataSource(pub u32);
#[derive(Clone, Copy, Debug)]
pub struct Packet(pub u32);
#[derive(Clone, Copy, Debug)]
pub struct Field(pub u32);
#[derive(Clone, Copy, Debug)]
pub struct Data(pub u32);
#[derive(Clone, Copy, Debug)]
pub struct DataArray(pub u32);
#[derive(Clone, Copy, Debug)]
pub struct PacketSingle(pub u32);
#[derive(Clone, Copy, Debug)]
pub struct PacketArray(pub u32);

impl DataSource {
    pub fn new_datasource(name: String, typ: DataSourceType) -> Result<Self> {
        let ptr = string_to_buf_ptr(name.as_str());
        let handle = unsafe { _new_datasource(ptr, typ as u32) };

        if handle == 0 {
            Err(DataSourceError::CreationFailed(name))
        } else {
            Ok(Self(handle))
        }
    }

    pub fn get_datasource(name: String) -> Result<Self> {
        let ptr = string_to_buf_ptr(name.as_str());
        let handle = unsafe { _get_datasource(ptr) };
        if handle == 0 {
            Err(DataSourceError::NotFound(name))
        } else {
            Ok(Self(handle))
        }
    }

    fn subscribe(&self, typ: SubscriptionType, prio: u32, cb: CallBack) -> Result<()> {
        let ctr = DS_SUBSCRIPTION_CTR.fetch_add(1, Ordering::SeqCst) + 1;
        DS_SUBCRIPTION
            .lock()
            .unwrap()
            .insert(ctr, Subscription { typ, cb });
        let ret = unsafe { _subscribe(self.0, typ as u32, prio, ctr) };
        if ret != 0 {
            Err(DataSourceError::SubscribingFailed)
        } else {
            Ok(())
        }
    }

    pub fn subscribe_data<F>(&self, cb: F, prio: u32) -> Result<()>
    where
        F: Fn(DataSource, Data) + Send + Sync + 'static,
    {
        self.subscribe(SubscriptionType::Data, prio, CallBack::Data(Arc::new(cb)))
    }

    pub fn subscribe_array<F>(&self, cb: F, prio: u32) -> Result<()>
    where
        F: Fn(DataSource, DataArray) -> Result<()> + Send + Sync + 'static,
    {
        self.subscribe(SubscriptionType::Array, prio, CallBack::Array(Arc::new(cb)))
    }

    pub fn subscribe_packet<F>(&self, cb: F, prio: u32) -> Result<()>
    where
        F: Fn(DataSource, Packet) -> Result<()> + Send + Sync + 'static,
    {
        self.subscribe(
            SubscriptionType::Packet,
            prio,
            CallBack::Packet(Arc::new(cb)),
        )
    }

    pub fn get_field(&self, name: &str) -> Result<Field> {
        let ptr = string_to_buf_ptr(name);
        let ret = unsafe { _get_field(self.0, ptr) };
        if ret == 0 {
            Err(DataSourceError::NotFound(name.to_string()))
        } else {
            Ok(Field(ret))
        }
    }

    pub fn add_field(&self, name: &str, kind: FieldKind) -> Result<Field> {
        let ptr = string_to_buf_ptr(name);
        let ret = unsafe { _add_field(self.0, ptr, kind as u32) };
        if ret == 0 {
            Err(DataSourceError::AddFieldFailed(name.to_string()))
        } else {
            Ok(Field(ret))
        }
    }

    pub fn new_packet_single(&self) -> Result<PacketSingle> {
        let ret = unsafe { _new_packet_single(self.0) };
        if ret == 0 {
            Err(DataSourceError::PacketCreationFailed)
        } else {
            Ok(PacketSingle(ret))
        }
    }

    pub fn new_packet_array(&self) -> Result<PacketArray> {
        let ret = unsafe { _new_packet_array(self.0) };
        if ret == 0 {
            Err(DataSourceError::PacketCreationFailed)
        } else {
            Ok(PacketArray(ret))
        }
    }

    pub fn emit_and_release(&self, packet: Packet) -> Result<()> {
        let ret = unsafe { _emit_and_release(self.0, packet.0) };
        if ret != 0 {
            Err(DataSourceError::EmitFailed)
        } else {
            Ok(())
        }
    }

    pub fn release(&self, packet: Packet) -> Result<()> {
        let ret = unsafe { _release(self.0, packet.0) };
        if ret != 0 {
            Err(DataSourceError::ReleaseFailed)
        } else {
            Ok(())
        }
    }

    pub fn unreference(&self) -> Result<()> {
        let ret = unsafe { _unreference(self.0) };
        if ret != 0 {
            Err(DataSourceError::UnreferenceFailed)
        } else {
            Ok(())
        }
    }

    pub fn is_referenced(&self) -> bool {
        unsafe { _is_referenced(self.0) == 1 }
    }
}

impl DataArray {
    pub fn new(&self) -> Data {
        let data = unsafe { _dataarray_new(self.0) };
        Data(data)
    }

    pub fn append(&self, data: Data) -> Result<()> {
        let ret = unsafe { _dataarray_append(self.0, data.0) };
        if ret != 0 {
            Err(DataSourceError::AppendFailed)
        } else {
            Ok(())
        }
    }

    pub fn release(&self, data: Data) -> Result<()> {
        let ret = unsafe { _dataarray_release(self.0, data.0) };
        if ret != 0 {
            Err(DataSourceError::ReleaseFailed)
        } else {
            Ok(())
        }
    }

    pub fn len(&self) -> usize {
        unsafe { _dataarray_len(self.0) as usize }
    }

    pub fn get(&self, index: usize) -> Data {
        Data(unsafe { _dataarray_get(self.0, index as u32) })
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub fn dataSourceCallback(cb_id: u64, ds: u32, data: u32) {
    let subscription = DS_SUBCRIPTION.lock().unwrap();
    let Some(sub) = subscription.get(&cb_id) else {
        return;
    };

    match &sub.cb {
        CallBack::Data(cb) => {
            cb(DataSource(ds), Data(data));
        }
        CallBack::Array(cb) => {
            let _ = cb(DataSource(ds), DataArray(data));
        }
        CallBack::Packet(cb) => {
            let _ = cb(DataSource(ds), Packet(data));
        }
    }
}

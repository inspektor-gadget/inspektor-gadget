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

use crate::datasources::{Data, Field, FieldKind};
use crate::helpers::{bytes_to_buf_ptr, from_c_string, string_to_buf_ptr}; //relative paths may hinder in testing.
use std::any::Any;

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "fieldGetScalar"]
    fn _get_scalar(field: u32, data: u32, kind: u32, err_ptr: u32) -> u64;
    #[link_name = "fieldGetBuffer"]
    fn _get_buffer(field: u32, data: u32, kind: u32, dst: u64) -> i32;
    #[link_name = "fieldSet"]
    fn _set(field: u32, data: u32, kind: u32, value: u64) -> u32;
    #[link_name = "fieldAddTag"]
    fn _add_tag(field: u32, tag: u64) -> u32;
}

pub type Result<T> = std::result::Result<T, String>;

pub enum FieldData {
    Bool(bool),
    Float32(f32),
    Float64(f64),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
}

impl Field {
    fn get_scalar(&self, data: Data, kind: FieldKind) -> Result<u64> {
        let mut err: u32 = 0;
        let err_ptr = &mut err as *mut u32 as u32;
        let val = unsafe { _get_scalar(self.0, data.0, kind as u32, err_ptr) };
        if err != 0 {
            return Err(String::from("Error getting field"));
        }
        Ok(val)
    }

    fn set(&self, data: Data, kind: FieldKind, value: u64) -> Result<()> {
        let ret = unsafe { _set(self.0, data.0, kind as u32, value) };
        if ret != 0 {
            return Err(String::from("Error setting field"));
        }
        Ok(())
    }

    pub fn get_data(&self, data: Data, field_kind: FieldKind) -> Result<FieldData> {
        match field_kind {
            FieldKind::Bool => {
                let val = self.get_scalar(data, FieldKind::Bool).map(|v| v == 1)?;
                Ok(FieldData::Bool(val))
            }
            FieldKind::Float32 => {
                let val = self.get_scalar(data, FieldKind::Float32).map(|v| f32::from_bits(v as u32))?;
                Ok(FieldData::Float32(val))
            }
            FieldKind::Float64 => {
                let val = self.get_scalar(data, FieldKind::Float64).map(f64::from_bits)?;
                Ok(FieldData::Float64(val))
            }
            FieldKind::Bytes => Err("Use bytes function".to_string()),
            FieldKind::String => Err("Use string function".to_string()),
            FieldKind::Int8 => {
                let val = self.get_scalar(data, FieldKind::Int8).map(|v| v as i8)?;
                Ok(FieldData::Int8(val))
            }
            FieldKind::Int16 => {
                let val = self.get_scalar(data, FieldKind::Int16).map(|v| v as i16)?;
                Ok(FieldData::Int16(val))
            }
            FieldKind::Int32 => {
                let val = self.get_scalar(data, FieldKind::Int32).map(|v| v as i32)?;
                Ok(FieldData::Int32(val))
            }
            FieldKind::Int64 => {
                let val = self.get_scalar(data, FieldKind::Int64).map(|v| v as i64)?;
                Ok(FieldData::Int64(val))
            }
            FieldKind::Uint8 => {
                let val = self.get_scalar(data, FieldKind::Uint8).map(|v| v as u8)?;
                Ok(FieldData::Uint8(val))
            }
            FieldKind::Uint16 => {
                let val = self.get_scalar(data, FieldKind::Uint16).map(|v| v as u16)?;
                Ok(FieldData::Uint16(val))
            }
            FieldKind::Uint32 => {
                let val = self.get_scalar(data, FieldKind::Uint32).map(|v| v as u32)?;
                Ok(FieldData::Uint32(val))
            }
            FieldKind::Uint64 => {
                let val = self.get_scalar(data, FieldKind::Uint64)?;
                Ok(FieldData::Uint64(val))
            }
            FieldKind::CString => Err("FieldKind CString is invalid".to_string()),
        }
    }

    pub fn set_data(&self, data: Data, value: &(dyn Any + Send)) -> Result<()> {
        if let Some(bool_val) = value.downcast_ref::<bool>() {
            return self.set(data, FieldKind::Bool, if *bool_val { 1 } else { 0 });
        }
        if let Some(float_val) = value.downcast_ref::<f32>() {
            return self.set(data, FieldKind::Float32, float_val.to_bits() as u64);
        }
        if let Some(float_val) = value.downcast_ref::<f64>() {
            return self.set(data, FieldKind::Float64, float_val.to_bits());
        }
        if let Some(bytes) = value.downcast_ref::<&[u8]>() {
            return self.set(data, FieldKind::Bytes, bytes_to_buf_ptr(bytes));
        }
        if let Some(string_val) = value.downcast_ref::<String>() {
            return self.set(data, FieldKind::String, string_to_buf_ptr(string_val));
        }
        if let Some(val) = value.downcast_ref::<i8>() {
            return self.set(data, FieldKind::Int8, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<i16>() {
            return self.set(data, FieldKind::Int16, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<i32>() {
            return self.set(data, FieldKind::Int32, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<i64>() {
            return self.set(data, FieldKind::Int64, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<u8>() {
            return self.set(data, FieldKind::Uint8, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<u16>() {
            return self.set(data, FieldKind::Uint16, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<u32>() {
            return self.set(data, FieldKind::Uint32, *val as u64);
        }
        if let Some(val) = value.downcast_ref::<u64>() {
            return self.set(data, FieldKind::Uint64, *val);
        }

        Err("Unsupported value type".to_string())
    }
    

    pub fn string(&self, data: Data, max_size: u32) -> Result<String> {
        let buffer = vec![0u8; max_size as usize];
        let n = self.bytes(data, &buffer);
        match n {
            Ok(ret) => Ok(from_c_string(&buffer[0..ret as usize])),
            Err(field_err) => Err(field_err),
        }
    }

    pub fn bytes(&self, data: Data, dst: &[u8]) -> Result<u32> {
        let ret = unsafe {
            _get_buffer(
                self.0,
                data.0,
                FieldKind::Bytes as u32,
                bytes_to_buf_ptr(dst),
            )
        };
        if ret == -1 {
            return Err(String::from("Error getting bytes"));
        }
        Ok(ret as u32)
    }

    pub fn add_tag(&self, tag: &str) -> Result<()> {
        let ret = unsafe { _add_tag(self.0, string_to_buf_ptr(tag)) };
        if ret != 0 {
            return Err(String::from("Error adding tag"));
        }
        Ok(())
    }
}

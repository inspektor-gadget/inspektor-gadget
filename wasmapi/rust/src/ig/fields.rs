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

use crate::ig::datasources::{Data, Field, FieldKind};
use crate::ig::helpers::{bytes_to_buf_ptr, from_c_string, string_to_buf_ptr}; //relative paths may hinder in testing.
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

pub enum FieldKindData {
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

    pub fn get_data(&self, data: Data, field_kind: FieldKind) -> Result<FieldKindData> {
        match field_kind {
            FieldKind::Bool => {
                let val = self.get_scalar(data, FieldKind::Bool).map(|v| v == 1)?;
                Ok(FieldKindData::Bool(val))
            }
            FieldKind::Float32 => {
                let val = self
                    .get_scalar(data, FieldKind::Float32)
                    .map(|v| f32::from_bits(v as u32))?;
                Ok(FieldKindData::Float32(val))
            }
            FieldKind::Float64 => {
                let val = self
                    .get_scalar(data, FieldKind::Float64)
                    .map(f64::from_bits)?;
                Ok(FieldKindData::Float64(val))
            }
            FieldKind::Bytes => Err("Use bytes function".to_string()),
            FieldKind::String => Err("Use string function".to_string()),
            FieldKind::Int8 => {
                let val = self.get_scalar(data, FieldKind::Int8).map(|v| v as i8)?;
                Ok(FieldKindData::Int8(val))
            }
            FieldKind::Int16 => {
                let val = self.get_scalar(data, FieldKind::Int16).map(|v| v as i16)?;
                Ok(FieldKindData::Int16(val))
            }
            FieldKind::Int32 => {
                let val = self.get_scalar(data, FieldKind::Int32).map(|v| v as i32)?;
                Ok(FieldKindData::Int32(val))
            }
            FieldKind::Int64 => {
                let val = self.get_scalar(data, FieldKind::Int64).map(|v| v as i64)?;
                Ok(FieldKindData::Int64(val))
            }
            FieldKind::Uint8 => {
                let val = self.get_scalar(data, FieldKind::Uint8).map(|v| v as u8)?;
                Ok(FieldKindData::Uint8(val))
            }
            FieldKind::Uint16 => {
                let val = self.get_scalar(data, FieldKind::Uint16).map(|v| v as u16)?;
                Ok(FieldKindData::Uint16(val))
            }
            FieldKind::Uint32 => {
                let val = self.get_scalar(data, FieldKind::Uint32).map(|v| v as u32)?;
                Ok(FieldKindData::Uint32(val))
            }
            FieldKind::Uint64 => {
                let val = self.get_scalar(data, FieldKind::Uint64)?;
                Ok(FieldKindData::Uint64(val))
            }
            _ => Err("Cannot get field for CString".to_string()),
        }
    }

    pub fn set_data(
        &self,
        data: Data,
        value: &(dyn Any + Send),
        field_kind: FieldKind,
    ) -> Result<()> {
        match field_kind {
            FieldKind::Bool => {
                if let Some(bool_val) = value.downcast_ref::<bool>() {
                    self.set(data, field_kind, if *bool_val { 1 } else { 0 })
                } else {
                    Err("Expected bool".to_string())
                }
            }
            FieldKind::Float32 => {
                if let Some(float_val) = value.downcast_ref::<f32>() {
                    self.set(data, field_kind, float_val.to_bits() as u64)
                } else {
                    Err("Expected f32".to_string())
                }
            }
            FieldKind::Float64 => {
                if let Some(float_val) = value.downcast_ref::<f64>() {
                    self.set(data, field_kind, float_val.to_bits())
                } else {
                    Err("Expected f64".to_string())
                }
            }
            FieldKind::Bytes => {
                if let Some(bytes) = value.downcast_ref::<&[u8]>() {
                    self.set(data, field_kind, bytes_to_buf_ptr(bytes))
                } else {
                    Err("Expected &[u8]".to_string())
                }
            }
            FieldKind::String => {
                if let Some(string_val) = value.downcast_ref::<String>() {
                    self.set(data, field_kind, string_to_buf_ptr(string_val))
                } else {
                    Err("Expected String".to_string())
                }
            }
            FieldKind::Invalid => Err("Invalid field".to_string()),
            FieldKind::Int8 => {
                if let Some(val) = value.downcast_ref::<i8>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected i8".to_string())
                }
            }
            FieldKind::Int16 => {
                if let Some(val) = value.downcast_ref::<i16>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected i16".to_string())
                }
            }
            FieldKind::Int32 => {
                if let Some(val) = value.downcast_ref::<i32>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected i32".to_string())
                }
            }
            FieldKind::Int64 => {
                if let Some(val) = value.downcast_ref::<i64>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected i64".to_string())
                }
            }
            FieldKind::Uint8 => {
                if let Some(val) = value.downcast_ref::<u8>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected u8".to_string())
                }
            }
            FieldKind::Uint16 => {
                if let Some(val) = value.downcast_ref::<u16>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected u16".to_string())
                }
            }
            FieldKind::Uint32 => {
                if let Some(val) = value.downcast_ref::<u32>() {
                    self.set(data, field_kind, *val as u64)
                } else {
                    Err("Expected u32".to_string())
                }
            }
            FieldKind::Uint64 => {
                if let Some(val) = value.downcast_ref::<u64>() {
                    self.set(data, field_kind, *val)
                } else {
                    Err("Expected u64".to_string())
                }
            }
            _ => Err("Can not set field for CString".to_string()),
        }
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

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

use crate::rust_bindings::datasources::{Data, Field, FieldKind};
use crate::rust_bindings::helpers::{bytes_to_buf_ptr, string_to_buf_ptr}; //relative paths may hinder in testing.

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "fieldGetScalar"]
    fn field_get_scalar(field: u32, data: u32, kind: u32, err_ptr: u32) -> u64;
    #[link_name = "fieldGetBuffer"]
    fn field_get_buffer(field: u32, data: u32, kind: u32, dst: u64) -> i32;
    #[link_name = "fieldSet"]
    fn field_set(field: u32, data: u32, kind: u32, value: u64) -> u32;
    #[link_name = "fieldAddTag"]
    fn field_add_tag(field: u32, tag: u64) -> u32;
}

// #[derive(Debug)]
// pub struct Field(u32);

pub enum FieldError {
    ErrSetField(String),
    ErrGetField(String),
    ErrGetString(String),
    ErrAddTag(String),
    ErrGetBytes(String),
}

pub type Result<T> = std::result::Result<T, FieldError>;

impl Field {
    pub fn get_scalar(&self, data: Data, kind: FieldKind) -> Result<u64> {
        let mut err: u32 = 0;
        let err_ptr = &mut err as *mut u32 as usize as u32;
        let val = unsafe { field_get_scalar(self.0, data.0, kind as u32, err_ptr) };
        if err != 0 {
            return Err(FieldError::ErrGetField(String::from("Error getting field")));
        }
        Ok(val)
    }

    pub fn set(&self, data: Data, kind: FieldKind, value: u64) -> Result<()> {
        let ret = unsafe { field_set(self.0, data.0, kind as u32, value) };
        if ret != 0 {
            return Err(FieldError::ErrSetField(String::from("Error setting field")));
        }
        Ok(())
    }

    pub fn int8(&self, data: Data) -> Result<i8> {
        self.get_scalar(data, FieldKind::Int8).map(|v| v as i8)
    }

    pub fn set_int8(&self, data: Data, value: i8) -> Result<()> {
        self.set(data, FieldKind::Int8, value as u64)
    }

    pub fn int16(&self, data: Data) -> Result<i16> {
        self.get_scalar(data, FieldKind::Int16).map(|v| v as i16)
    }

    pub fn set_int16(&self, data: Data, value: i16) -> Result<()> {
        self.set(data, FieldKind::Int16, value as u64)
    }

    pub fn int32(&self, data: Data) -> Result<i32> {
        self.get_scalar(data, FieldKind::Int32).map(|v| v as i32)
    }

    pub fn set_int32(&self, data: Data, value: i32) -> Result<()> {
        self.set(data, FieldKind::Int32, value as u64)
    }

    pub fn int64(&self, data: Data) -> Result<i64> {
        self.get_scalar(data, FieldKind::Int64).map(|v| v as i64)
    }

    pub fn set_int64(&self, data: Data, value: i64) -> Result<()> {
        self.set(data, FieldKind::Int64, value as u64)
    }

    pub fn uint8(&self, data: Data) -> Result<u8> {
        self.get_scalar(data, FieldKind::Uint8).map(|v| v as u8)
    }

    pub fn set_uint8(&self, data: Data, value: u8) -> Result<()> {
        self.set(data, FieldKind::Uint8, value as u64)
    }

    pub fn uint16(&self, data: Data) -> Result<u16> {
        self.get_scalar(data, FieldKind::Uint16).map(|v| v as u16)
    }

    pub fn set_uint16(&self, data: Data, value: u16) -> Result<()> {
        self.set(data, FieldKind::Uint16, value as u64)
    }

    pub fn uint32(&self, data: Data) -> Result<u32> {
        self.get_scalar(data, FieldKind::Uint32).map(|v| v as u32)
    }

    pub fn set_uint32(&self, data: Data, value: u32) -> Result<()> {
        self.set(data, FieldKind::Uint32, value as u64)
    }

    pub fn uint64(&self, data: Data) -> Result<u64> {
        self.get_scalar(data, FieldKind::Uint64)
    }

    pub fn set_uint64(&self, data: Data, value: u64) -> Result<()> {
        self.set(data, FieldKind::Uint64, value)
    }

    pub fn float32(&self, data: Data) -> Result<f32> {
        self.get_scalar(data, FieldKind::Float32)
            .map(|v| f32::from_bits(v as u32))
    }

    pub fn set_float32(&self, data: Data, value: f32) -> Result<()> {
        self.set(data, FieldKind::Float32, value.to_bits() as u64)
    }

    pub fn float64(&self, data: Data) -> Result<f64> {
        self.get_scalar(data, FieldKind::Float64)
            .map(f64::from_bits)
    }

    pub fn set_float64(&self, data: Data, value: f64) -> Result<()> {
        self.set(data, FieldKind::Float64, value.to_bits())
    }

    pub fn boolean(&self, data: Data) -> Result<bool> {
        self.get_scalar(data, FieldKind::Bool).map(|v| v == 1)
    }

    pub fn set_boolean(&self, data: Data, value: bool) -> Result<()> {
        self.set(data, FieldKind::Bool, if value { 1 } else { 0 })
    }

    pub fn string(&self, data: Data, max_size: u32) -> Result<String> {
        let mut buffer = vec![0u8; max_size as usize];
        let n = self.bytes(data, &buffer);
        match n {
            Ok(ret) => Ok(String::from_utf8_lossy(&buffer[..ret as usize]).to_string()), //similar to fromCstring
            Err(field_err) => Err(field_err),
        }
    }

    pub fn set_string(&self, data: Data, value: &str) -> Result<()> {
        self.set(data, FieldKind::String, string_to_buf_ptr(value))
    }

    pub fn bytes(&self, data: Data, dst: &[u8]) -> Result<u32> {
        let ret = unsafe {
            field_get_buffer(
                self.0,
                data.0,
                FieldKind::Bytes as u32,
                bytes_to_buf_ptr(&dst),
            )
        };
        if ret == -1 {
            return Err(FieldError::ErrGetBytes(String::from("Error getting bytes")));
        }
        Ok(ret as u32)
    }

    pub fn add_tag(&self, tag: &str) -> Result<()> {
        let ret = unsafe { field_add_tag(self.0, string_to_buf_ptr(tag)) };
        if ret != 0 {
            return Err(FieldError::ErrAddTag(String::from("Error adding tag")));
        }

        Ok(())
    }
}

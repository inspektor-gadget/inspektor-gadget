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
use crate::ig::helpers::{any_to_buf_ptr_mut, bytes_to_buf_ptr, from_c_string, string_to_buf_ptr};

#[link(wasm_import_module = "ig")]
extern "C" {
    #[link_name = "getSyscallName"]
    fn _name(id: u32, dst: u64) -> u32;
    #[link_name = "getSyscallID"]
    fn _id(name: u64) -> i32;
    #[link_name = "getSyscallDeclaration"]
    fn _declaration(name: u64, pointer: u64) -> u32;
}

pub const IS_POINTER_FLAG: u32 = 1;
pub const MAX_SYSCALL_LENGTH: usize = 64;

pub type Result<T> = std::result::Result<T, String>;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct SyscallParamRaw {
    name: [u8; 32],
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct SyscallDeclarationRaw {
    name: [u8; 32],
    nr_params: u8,
    _padding: [u8; 3],
    params: [SyscallParamRaw; 6],
}

#[derive(Debug)]
pub struct SyscallParam {
    pub name: String,
    pub is_pointer: bool,
}

#[derive(Debug)]
pub struct SyscallDeclaration {
    pub name: String,
    pub params: Vec<SyscallParam>,
}

pub fn get_syscall_name(id: u16) -> Result<String> {
    let dst = [0u8; MAX_SYSCALL_LENGTH];
    let result = unsafe { _name(id as u32, bytes_to_buf_ptr(&dst) as u64) };

    if result == 1 {
        Err(format!("getting syscall name for syscall id {}", id))
    } else {
        Ok(from_c_string(&dst))
    }
}

pub fn get_syscall_id(name: String) -> Result<i32> {
    let id = unsafe { _id(string_to_buf_ptr(&name)) };

    if id == -1 {
        Err(format!("getting syscall ID for syscall {}", name))
    } else {
        Ok(id)
    }
}

pub fn get_syscall_declaration(name: &str) -> Result<SyscallDeclaration> {
    let mut raw_decl = SyscallDeclarationRaw::default();
    let buf_ptr = any_to_buf_ptr_mut(&mut raw_decl).expect("Invalid raw syscall declaration");
    let ret = unsafe { _declaration(string_to_buf_ptr(name) as u64, buf_ptr) };

    if ret == 1 {
        return Err(format!("syscall declaration {} not found", name));
    }

    let syscall_name = from_c_string(&raw_decl.name);
    let mut params = Vec::with_capacity(raw_decl.nr_params as usize);
    for i in 0..raw_decl.nr_params as usize {
        let raw_param = &raw_decl.params[i];
        params.push(SyscallParam {
            name: from_c_string(&raw_param.name),
            is_pointer: (raw_param.flags & IS_POINTER_FLAG) != 0,
        });
    }

    Ok(SyscallDeclaration {
        name: syscall_name,
        params,
    })
}

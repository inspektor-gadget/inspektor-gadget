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

use std::mem;

use crate::rust_bindings::helpers::{bytes_to_buf_ptr, from_c_string, string_to_buf_ptr};

extern "C" {
    #[link_name = "getSyscallName"]
    fn get_Syscall_name(id: u32, dst: u64) -> u32;
    #[link_name = "getSyscallID"]
    fn get_Syscall_id(name: u64) -> i32;
    #[link_name = "getSyscallDeclaration"]
    fn get_Syscall_declaration(name: u64, pointer: u64) -> u32;
}

pub const IS_POINTER_FLAG: u32 = 1;
pub const MAX_SYSCALL_LENGTH: usize = 64;

pub type Result<T> = std::result::Result<T, ErrSyscall>;

pub enum ErrSyscall {
    ErrSysName(String),
    ErrSysID(String),
    ErrDecSys(String),
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallParamRaw {
    pub name: [u8; 32],
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallDeclarationRaw {
    pub name: [u8; 32],
    pub nr_params: u8,
    _padding: [u8; 3],
    pub params: [SyscallParamRaw; 6],
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
    let mut dst = [0u8; MAX_SYSCALL_LENGTH];
    let result = unsafe { get_Syscall_name(id as u32, bytes_to_buf_ptr(&dst) as u64) };

    if result == 1 {
        return Err(ErrSyscall::ErrSysName(String::from(format!(
            "getting syscall name for syscall id {}",
            id
        ))));
    }
    Ok(from_c_string(&dst))
}

pub fn get_syscall_id(name: String) -> Result<i32> {
    let id = unsafe { get_Syscall_id(string_to_buf_ptr(&name)) };

    if id == -1 {
        return Err(ErrSyscall::ErrSysID(String::from(format!(
            "getting syscall ID for syscall {}",
            name
        ))));
    }
    Ok(id)
}

pub fn get_syscall_declaration(name: &str) -> Result<SyscallDeclaration> {
    let mut raw_decl = SyscallDeclarationRaw {
        name: [0; 32],
        nr_params: 0,
        _padding: [0; 3],
        params: [SyscallParamRaw {
            name: [0; 32],
            flags: 0,
        }; 6],
    };

    let decl_ptr = &mut raw_decl as *const SyscallDeclarationRaw as u64;
    let size = mem::size_of::<SyscallDeclarationRaw>() as u64;
    let bufPtr = (size << 32) | decl_ptr;
    let ret = unsafe { get_Syscall_declaration(string_to_buf_ptr(name) as u64, bufPtr) };

    if ret == 1 {
        return Err(ErrSyscall::ErrDecSys(String::from(format!(
            "syscall declaration {} not found",
            name
        ))));
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

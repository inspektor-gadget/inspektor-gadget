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

use api::ig::{
	datasources::{Data, DataSource, FieldKind},
	fields::FieldKindData,
	log::LogLevel,
};

fn get_call_str(op: i32, src: String, target: String, fs: String, flags: String, data: String, error_raw: u32) -> String {
	match op {
		0 => format!(r#"mount("{}", "{}", "{}", {}, "{}") = {}"#, src, target, fs, flags, data, error_raw),
		1 => format!(r#"umount("{}", "{}") = {}"#, target, flags, error_raw),
		_ => "".to_string(),
	}
}

#[no_mangle]
#[allow(non_snake_case)]
fn gadgetInit() -> i32 {
	let ds = match DataSource::get_datasource("mount".to_string()) {
		Ok(ds) => ds,
		Err(e) => {
			api::errorf!("failed to get datasource: {:?}", e);
			return 1;
		}
	};

	let op_raw_field = match ds.get_field("op_raw") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let src_field = match ds.get_field("src") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let dest_field = match ds.get_field("dest") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let fs_field = match ds.get_field("fs") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let data_field = match ds.get_field("data") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let error_raw_field = match ds.get_field("error_raw") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let flags_field = match ds.get_field("flags") {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to get field: {:?}", e);
			return 1;
		}
	};

	let call_field = match ds.add_field("call", FieldKind::String) {
		Ok(f) => f,
		Err(e) => {
			api::errorf!("failed to add field: {:?}", e);
			return 1;
		}
	};

	let _ = ds.subscribe_data(move |_source: DataSource, data: Data| {
		let flags = match flags_field.string(data, 512) {
			Ok(flags) => flags,
			Err(_) => "".to_string(),
		};
		let op_raw = match op_raw_field.get_data(data, FieldKind::Int32) {
			Ok(FieldKindData::Int32(op_raw)) => op_raw,
			_ => 0,
		};
		let src = match src_field.string(data, 4096) {
			Ok(src) => src,
			Err(_) => "".to_string(),
		};
		let dest = match dest_field.string(data, 4096) {
			Ok(dest) => dest,
			Err(_) => "".to_string(),
		};
		let fs = match fs_field.string(data, 4096) {
			Ok(fs) => fs,
			Err(_) => "".to_string(),
		};
		let data_str = match data_field.string(data, 512) {
			Ok(data_str) => data_str,
			Err(_) => "".to_string(),
		};
		let error_raw = match error_raw_field.get_data(data, FieldKind::Uint32) {
			Ok(FieldKindData::Uint32(error_raw)) => error_raw,
			_ => 0,
		};

		let _ = call_field.set_data(data, &get_call_str(op_raw, src, dest, fs, flags, data_str, error_raw), FieldKind::String);
	}, 0,);

	0
}

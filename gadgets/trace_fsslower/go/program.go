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

package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

type fsConf struct {
	read   string
	write  string
	open   string
	fsync  string
	statfs string
}

var fsConfMap = map[string]fsConf{
	"btrfs": {
		read:   "btrfs_file_read_iter",
		write:  "btrfs_file_write_iter",
		open:   "btrfs_file_open",
		fsync:  "btrfs_sync_file",
		statfs: "btrfs_statfs",
	},
	"ext4": {
		read:   "ext4_file_read_iter",
		write:  "ext4_file_write_iter",
		open:   "ext4_file_open",
		fsync:  "ext4_sync_file",
		statfs: "ext4_statfs",
	},
	"fuse": {
		read:  "fuse_file_read_iter",
		write: "fuse_file_write_iter",
		open:  "fuse_open",
		fsync: "fuse_fsync",
		// fuse does not define statfs(), so let's skip it.
		statfs: "gadget_program_disabled",
	},
	"nfs": {
		read:   "nfs_file_read",
		write:  "nfs_file_write",
		open:   "nfs_file_open",
		fsync:  "nfs_file_fsync",
		statfs: "nfs_statfs",
	},
	"ntfs3": {
		read:  "ntfs_file_read_iter",
		write: "ntfs_file_write_iter",
		open:  "ntfs_file_open",
		fsync: "generic_file_fsync",
		// ntfs3 does not define statfs(), so let's skip it.
		statfs: "gadget_program_disabled",
	},
	"xfs": {
		read:   "xfs_file_read_iter",
		write:  "xfs_file_write_iter",
		open:   "xfs_file_open",
		fsync:  "xfs_file_fsync",
		statfs: "xfs_fs_statfs",
	},
}

//export gadgetPreStart
func gadgetPreStart() int {
	value, err := api.GetParamValue("filesystem")
	if err != nil {
		api.Errorf("failed to get param value: %s", err)
		return 1
	}

	config, ok := fsConfMap[value]
	if !ok {
		api.Errorf("filesystem %s not supported", value)
		return 1
	}

	api.SetConfig("programs.ig_fssl_read_e.attach_to", config.read)
	api.SetConfig("programs.ig_fssl_read_x.attach_to", config.read)
	api.SetConfig("programs.ig_fssl_wr_e.attach_to", config.write)
	api.SetConfig("programs.ig_fssl_wr_x.attach_to", config.write)
	api.SetConfig("programs.ig_fssl_open_e.attach_to", config.open)
	api.SetConfig("programs.ig_fssl_open_x.attach_to", config.open)
	api.SetConfig("programs.ig_fssl_sync_e.attach_to", config.fsync)
	api.SetConfig("programs.ig_fssl_sync_x.attach_to", config.fsync)
	api.SetConfig("programs.ig_fssl_statfs_e.attach_to", config.statfs)
	api.SetConfig("programs.ig_fssl_statfs_x.attach_to", config.statfs)

	return 0
}

func main() {}

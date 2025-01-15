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

package inode

import (
	"fmt"
	"os"
	"syscall"
)

// GetInode extracts the inode of a given path
func GetInode(path string) (uint64, error) {
	// Get information about the given path (file or directory)
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("attempting to stat path %s: %w", path, err)
	}

	// Extract the inode value from the system information
	sysInfo := fileInfo.Sys()
	if stat, ok := sysInfo.(*syscall.Stat_t); ok {
		return uint64(stat.Ino), nil
	}
	return 0, fmt.Errorf("encountering issues when asserting system info as *syscall.Stat_t for path: %s", path)
}


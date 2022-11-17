// Copyright 2019-2022 The Inspektor Gadget authors
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

package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func CgroupPathV2AddMountpoint(path string) (string, error) {
	pathWithMountpoint := filepath.Join("/sys/fs/cgroup/unified", path)
	if _, err := os.Stat(pathWithMountpoint); os.IsNotExist(err) {
		pathWithMountpoint = filepath.Join("/sys/fs/cgroup", path)
		if _, err := os.Stat(pathWithMountpoint); os.IsNotExist(err) {
			return "", fmt.Errorf("cannot access cgroup %q: %w", path, err)
		}
	}
	return pathWithMountpoint, nil
}

// GetCgroupID returns the cgroup2 ID of a path.
func GetCgroupID(pathWithMountpoint string) (uint64, error) {
	hf, _, err := unix.NameToHandleAt(unix.AT_FDCWD, pathWithMountpoint, 0)
	if err != nil {
		return 0, fmt.Errorf("GetCgroupID on %q failed: %w", pathWithMountpoint, err)
	}
	if hf.Size() != 8 {
		return 0, fmt.Errorf("GetCgroupID on %q failed: unexpected size", pathWithMountpoint)
	}
	ret := *(*uint64)(unsafe.Pointer(&hf.Bytes()[0]))
	return ret, nil
}

// GetCgroupPaths returns the cgroup1 and cgroup2 paths of a process.
// It does not include the "/sys/fs/cgroup/{unified,systemd,}" prefix.
func GetCgroupPaths(pid int) (string, string, error) {
	cgroupPathV1 := ""
	cgroupPathV2 := ""
	if cgroupFile, err := os.Open(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup")); err == nil {
		defer cgroupFile.Close()
		reader := bufio.NewReader(cgroupFile)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(line, "1:name=systemd:") {
				cgroupPathV1 = strings.TrimPrefix(line, "1:name=systemd:")
				cgroupPathV1 = strings.TrimSuffix(cgroupPathV1, "\n")
				continue
			}
			if strings.HasPrefix(line, "0::") {
				cgroupPathV2 = strings.TrimPrefix(line, "0::")
				cgroupPathV2 = strings.TrimSuffix(cgroupPathV2, "\n")
				continue
			}
		}
	} else {
		return "", "", fmt.Errorf("cannot parse cgroup: %w", err)
	}

	if cgroupPathV1 == "/" {
		cgroupPathV1 = ""
	}

	if cgroupPathV2 == "/" {
		cgroupPathV2 = ""
	}

	if cgroupPathV2 == "" && cgroupPathV1 == "" {
		return "", "", fmt.Errorf("cannot find cgroup path in /proc/PID/cgroup")
	}

	return cgroupPathV1, cgroupPathV2, nil
}

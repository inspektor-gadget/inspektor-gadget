// Copyright 2019-2021 The Inspektor Gadget authors
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

package containerutils

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
)

/*
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

struct cgid_file_handle
{
  //struct file_handle handle;
  unsigned int handle_bytes;
  int handle_type;
  uint64_t cgid;
};

uint64_t get_cgroupid(char *path) {
  struct cgid_file_handle *h;
  int mount_id;
  int err;
  uint64_t ret;

  h = malloc(sizeof(struct cgid_file_handle));
  if (!h)
    return 0;

  h->handle_bytes = 8;
  err = name_to_handle_at(AT_FDCWD, path, (struct file_handle *)h, &mount_id, 0);
  if (err != 0)
    return 0;

  if (h->handle_bytes != 8)
    return 0;

  ret = h->cgid;
  free(h);

  return ret;
}
*/
import "C"

type CRIClient interface {
	Close() error
	PidFromContainerID(containerID string) (int, error)
}

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
	cPathWithMountpoint := C.CString(pathWithMountpoint)
	ret := uint64(C.get_cgroupid(cPathWithMountpoint))
	C.free(unsafe.Pointer(cPathWithMountpoint))
	if ret == 0 {
		return 0, fmt.Errorf("GetCgroupID on %q failed", pathWithMountpoint)
	}
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

func getNamespaceInode(pid int, nsType string) (uint64, error) {
	fileinfo, err := os.Stat(filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns", nsType))
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

func GetMntNs(pid int) (uint64, error) {
	return getNamespaceInode(pid, "mnt")
}

func GetNetNs(pid int) (uint64, error) {
	return getNamespaceInode(pid, "net")
}

func ParseOCIState(stateBuf []byte) (id string, pid int, err error) {
	ociState := &ocispec.State{}
	err = json.Unmarshal(stateBuf, ociState)
	if err != nil {
		// Some versions of runc produce an invalid json...
		// As a workaround, make it valid by trimming the invalid parts
		fix := regexp.MustCompile(`(?ms)^(.*),"annotations":.*$`)
		matches := fix.FindStringSubmatch(string(stateBuf))
		if len(matches) != 2 {
			err = fmt.Errorf("cannot parse OCI state: matches=%+v\n %w\n%s", matches, err, string(stateBuf))
			return
		}
		err = json.Unmarshal([]byte(matches[1]+"}"), ociState)
		if err != nil {
			err = fmt.Errorf("cannot parse OCI state: %w\n%s", err, string(stateBuf))
			return
		}
	}
	id = ociState.ID
	pid = ociState.Pid
	return
}

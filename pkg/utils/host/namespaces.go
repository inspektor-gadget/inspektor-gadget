//go:build linux
// +build linux

// Copyright 2023 The Inspektor Gadget authors
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

// Package host provides ways to access the host filesystem.
//
// Inspektor Gadget can run either in the host or in a container. When running
// in a container, the host filesystem must be available in a specific
// directory.
package host

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

var (
	onceHostPidNs sync.Once
	isHostPidNs   bool
	errHostPidNs  error

	onceHostNetNs sync.Once
	isHostNetNs   bool
	errHostNetNs  error
)

// IsHostPidNs returns true if the current process is running in the host PID namespace
func IsHostPidNs() (bool, error) {
	onceHostPidNs.Do(func() {
		isHostPidNs, errHostPidNs = isHostNamespace("pid")
	})
	return isHostPidNs, errHostPidNs
}

// IsHostNetNs returns true if the current process is running in the host network namespace
func IsHostNetNs() (bool, error) {
	onceHostNetNs.Do(func() {
		isHostNetNs, errHostNetNs = isHostNamespace("net")
	})
	return isHostNetNs, errHostNetNs
}

// isHostNamespace checks if the current process is running in the specified host namespace
func isHostNamespace(nsKind string) (bool, error) {
	if !initDone {
		// HostProcFs can be overwritten by workarounds, so Init() must be called first.
		panic("host.Init() must be called before calling isHostNamespace()")
	}

	selfFileInfo, err := os.Stat("/proc/self/ns/" + nsKind)
	if err != nil {
		return false, err
	}
	selfStat, ok := selfFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("reading inode of /proc/self/ns/%s", nsKind)
	}

	systemdFileInfo, err := os.Stat(fmt.Sprintf("%s/1/ns/%s", HostProcFs, nsKind))
	if err != nil {
		return false, err
	}
	systemdStat, ok := systemdFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("reading inode of %s/1/ns/%s", HostProcFs, nsKind)
	}

	return selfStat.Ino == systemdStat.Ino, nil
}

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

// Inode number of the PID namespace the kernel creates at boot time. It is
// allocated statically, see PROC_PID_INIT_INO in include/linux/proc_ns.h.
//
// The network and mount namespaces have no such constant: their initial
// instances get a dynamically allocated inode number.
const initPidNsInode = 0xEFFFFFFC // PROC_PID_INIT_INO

// namespaceInode returns the inode number of the given /proc/<pid>/ns/<kind> file
func namespaceInode(path string) (uint64, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("reading inode of %s", path)
	}
	return stat.Ino, nil
}

// selfNamespaceInode returns the inode number of the namespace of the given
// kind ("pid", "net", "cgroup"...) the current process belongs to
func selfNamespaceInode(nsKind string) (uint64, error) {
	return namespaceInode("/proc/self/ns/" + nsKind)
}

// IsInitPidNs returns true if the current process is running in the PID
// namespace the kernel created at boot time.
//
// This is stricter than IsHostPidNs(), which only compares with PID 1 as seen
// through HostProcFs: when the host itself is containerized, for instance a
// minikube node started with the docker driver, IsHostPidNs() can return true
// while this function returns false. Callers handling PIDs reported by eBPF
// programs must use this function, since those PIDs are always relative to the
// initial PID namespace.
func IsInitPidNs() (bool, error) {
	inode, err := selfNamespaceInode("pid")
	if err != nil {
		return false, err
	}
	return inode == initPidNsInode, nil
}

// IsHostPidNs returns true if the current process is running in the host PID namespace
func IsHostPidNs() (bool, error) {
	return sync.OnceValues[bool, error](func() (bool, error) {
		return isHostNamespace("pid")
	})()
}

// IsHostNetNs returns true if the current process is running in the host network namespace
func IsHostNetNs() (bool, error) {
	return sync.OnceValues[bool, error](func() (bool, error) {
		return isHostNamespace("net")
	})()
}

// IsHostCgroupNs returns true if the current process is running in the host cgroup namespace
func IsHostCgroupNs() (bool, error) {
	return sync.OnceValues[bool, error](func() (bool, error) {
		return isHostNamespace("cgroup")
	})()
}

// isHostNamespace checks if the current process is running in the specified host namespace
func isHostNamespace(nsKind string) (bool, error) {
	if !initDone {
		// HostProcFs can be overwritten by workarounds, so Init() must be called first.
		return false, fmt.Errorf("host.Init() must be called before calling isHostNamespace()")
	}

	selfInode, err := selfNamespaceInode(nsKind)
	if err != nil {
		return false, err
	}

	systemdInode, err := namespaceInode(fmt.Sprintf("%s/1/ns/%s", HostProcFs, nsKind))
	if err != nil {
		return false, err
	}

	return selfInode == systemdInode, nil
}

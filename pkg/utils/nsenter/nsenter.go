// Copyright 2021 The Inspektor Gadget authors
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

package nsenter

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	netnsig "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/netns"
)

// NetnsEnter enters the network namespace of a process and executes the provided function
func NetnsEnter(pid int, f func() error) error {
	if pid == 0 {
		return f()
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	netnsHandle, err := netnsig.GetFromPidWithAltProcfs(pid, host.HostProcFs)
	if err != nil {
		return err
	}
	defer netnsHandle.Close()
	err = netns.Set(netnsHandle)
	if err != nil {
		return err
	}

	// Switch back to the original namespace
	defer netns.Set(origns)

	return f()
}

// CgroupnsEnter enters the cgroup namespace of a process and executes the provided function
func CgroupnsEnter(pid int, f func() error) error {
	if pid == 0 {
		return f()
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current cgroup namespace
	origCgroupPath := filepath.Join("/proc", fmt.Sprint(os.Getpid()), "task", fmt.Sprint(unix.Gettid()), "ns", "cgroup")
	origns, err := unix.Open(origCgroupPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(origns)

	newCgroupPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid), "ns", "cgroup")
	cgroupnsHandle, err := unix.Open(newCgroupPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(cgroupnsHandle)
	err = unix.Setns(cgroupnsHandle, unix.CLONE_NEWCGROUP)
	if err != nil {
		return err
	}

	// Switch back to the original namespace
	defer unix.Setns(origns, unix.CLONE_NEWCGROUP)

	return f()
}

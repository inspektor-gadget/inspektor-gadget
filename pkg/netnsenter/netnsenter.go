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

package netnsenter

import (
	"runtime"

	"github.com/vishvananda/netns"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

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

	netnsHandle, err := netns.GetFromPidWithAltProcfs(pid, host.HostProcFs)
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

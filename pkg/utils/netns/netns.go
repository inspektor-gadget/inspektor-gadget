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

// Package netns is a small wrapper around github.com/vishvananda/netns that provides
// GetFromPidWithAltProcfs() and GetFromThreadWithAltProcfs().
// TODO: Remove once https://github.com/vishvananda/netns/pull/76 is merged
package netns

import (
	"fmt"

	"github.com/vishvananda/netns"
)

// GetFromPidWithAltProcfs gets a handle to the network namespace of a given
// pid using the specified procfs path.
func GetFromPidWithAltProcfs(pid int, procfs string) (netns.NsHandle, error) {
	return netns.GetFromPath(fmt.Sprintf("%s/%d/ns/net", procfs, pid))
}

// GetFromThreadWithAltProcfs gets a handle to the network namespace of a given
// pid and tid using the specified procfs path.
func GetFromThreadWithAltProcfs(pid, tid int, procfs string) (netns.NsHandle, error) {
	return netns.GetFromPath(fmt.Sprintf("%s/%d/task/%d/ns/net", procfs, pid, tid))
}

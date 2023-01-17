// Copyright 2022-2023 The Inspektor Gadget authors
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

package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	ProfileUserParam   = "user"
	ProfileKernelParam = "kernel"
)

type Report struct {
	eventtypes.CommonData

	Comm        string   `json:"comm,omitempty" column:"comm,template:comm"`
	Pid         uint32   `json:"pid,omitempty" column:"pid,template:pid"`
	UserStack   []string `json:"userStack,omitempty"`
	KernelStack []string `json:"kernelStack,omitempty"`
	Count       uint64   `json:"count,omitempty" column:"count"`

	MntnsID uint64 `json:"-"`
}

func GetColumns() *columns.Columns[Report] {
	return columns.MustCreateColumns[Report]()
}

func (r *Report) GetMountNSID() uint64 {
	return r.MntnsID
}

func (r *Report) ExtraLines() []string {
	var out []string
	for i := len(r.KernelStack) - 1; i >= 0; i-- {
		out = append(out, "\t"+r.KernelStack[i])
	}
	for i := len(r.UserStack) - 1; i >= 0; i-- {
		out = append(out, "\t"+r.UserStack[i])
	}
	return out
}

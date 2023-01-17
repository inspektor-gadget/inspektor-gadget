// Copyright 2019-2023 The Inspektor Gadget authors
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
	"fmt"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type SyscallParam struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type Event struct {
	eventtypes.Event

	CPU        uint16         `json:"cpu,omitempty" column:"cpu,width:3,fixed"`
	Pid        uint32         `json:"pid,omitempty" column:"pid,template:pid"`
	Comm       string         `json:"comm,omitempty" column:"comm,template:comm"`
	Syscall    string         `json:"syscall,omitempty" column:"syscall,template:syscall"`
	Parameters []SyscallParam `json:"parameters,omitempty" column:"params,width:40"`
	Retval     int            `json:"ret,omitempty" column:"ret,width:3,fixed"`
	MountNsID  uint64         `json:"mountnsid,omitempty" column:"mntns,template:ns"`
}

type TraceloopInfo struct {
	Node          string `json:"node,omitempty" column:"node,template:node"`
	Namespace     string `json:"namespace,omitempty" column:"namespace,template:namespace"`
	Podname       string `json:"podname,omitempty" column:"pod,template:pod"`
	Containername string `json:"containername,omitempty" column:"container,template:container"`
	ContainerID   string `json:"containerID,omitempty" column:"containerID,minWidth:12,ellipsis:none"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.SetExtractor("params", func(event *Event) (ret string) {
		var sb strings.Builder

		for idx, p := range event.Parameters {
			sb.WriteString(fmt.Sprintf("%s=%s", p.Name, p.Value))

			if idx < len(event.Parameters)-1 {
				sb.WriteString(", ")
			}
		}

		return sb.String()
	})
	cols.SetExtractor("ret", func(event *Event) (ret string) {
		// There is no exit event for exit(), exit_group() and rt_sigreturn().
		if event.Syscall == "exit" || event.Syscall == "exit_group" || event.Syscall == "rt_sigreturn" {
			return "X"
		}
		return strconv.Itoa(event.Retval)
	})

	// We hide these fields to gain some places for the parameters.
	// Indeed, namespace, podname and containername are printed by the list
	// subcommand.
	// They can be printed later nonetheless, for example by using
	// -o custom-columns.
	columns := []string{"node", "namespace", "pod", "container"}
	for _, name := range columns {
		column, ok := cols.GetColumn(name)
		if !ok {
			panic(fmt.Sprintf("no column %q\n", name))
		}

		column.Visible = false
	}

	return cols
}

func GetInfoColumns() *columns.Columns[TraceloopInfo] {
	return columns.MustCreateColumns[TraceloopInfo]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

func (ev *Event) GetMountNSID() uint64 {
	return ev.MountNsID
}

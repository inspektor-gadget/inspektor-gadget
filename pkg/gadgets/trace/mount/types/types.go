// Copyright 2022 The Inspektor Gadget authors
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
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Comm      string   `json:"comm,omitempty" column:"comm,template:comm"`
	Pid       uint32   `json:"pid,omitempty" column:"pid,template:pid"`
	Tid       uint32   `json:"tid,omitempty" column:"tid,template:pid"`
	MountNsID uint64   `json:"mntnsid,omitempty" column:"mntns,template:ns"`
	Operation string   `json:"operation,omitempty" column:"op,minWidth:5,maxWidth:7,hide"`
	Retval    int      `json:"ret,omitempty" column:"ret,width:3,fixed,hide"`
	Latency   uint64   `json:"latency,omitempty" column:"latency,minWidth:3,hide"`
	Fs        string   `json:"fs,omitempty" column:"fs,minWidth:3,maxWidth:8,hide"`
	Source    string   `json:"source,omitempty" column:"src,width:16,hide"`
	Target    string   `json:"target,omitempty" column:"dst,width:16,hide"`
	Data      string   `json:"data,omitempty" column:"data,width:16,hide"`
	Flags     []string `json:"flags,omitempty" column:"flags,width:24,hide"`
	FlagsRaw  uint64   `json:"flagsRaw,omitempty"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.MustAddColumn(columns.Column[Event]{
		Name:    "call",
		Width:   80,
		Visible: true,
		Order:   1000,
		Extractor: func(e *Event) string {
			switch e.Operation {
			case "mount":
				format := `mount("%s", "%s", "%s", %s, "%s") = %d`
				return fmt.Sprintf(format, e.Source, e.Target, e.Fs, strings.Join(e.Flags, " | "),
					e.Data, e.Retval)
			case "umount":
				format := `umount("%s", %s) = %d`
				return fmt.Sprintf(format, e.Target, strings.Join(e.Flags, " | "), e.Retval)
			}

			return ""
		},
	})

	cols.MustSetExtractor("flags", func(event *Event) string {
		return strings.Join(event.Flags, " | ")
	})

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

func (ev *Event) GetMountNSID() uint64 {
	return ev.MountNsID
}

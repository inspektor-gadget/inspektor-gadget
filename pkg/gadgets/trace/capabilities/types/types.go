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
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	AuditOnlyDefault = true
	UniqueDefault    = false
)

const (
	AuditOnlyParam = "audit-only"
	UniqueParam    = "unique"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid           uint32   `json:"pid,omitempty" column:"pid,template:pid"`
	Comm          string   `json:"comm,omitempty" column:"comm,template:comm"`
	Syscall       string   `json:"syscall,omitempty" column:"syscall,template:syscall"`
	Uid           uint32   `json:"uid" column:"uid,template:uid,hide"`
	Gid           uint32   `json:"gid" column:"gid,template:gid,hide"`
	Cap           int      `json:"cap,omitempty" column:"cap,width:3,fixed"`
	CapName       string   `json:"capName,omitempty" column:"capName,width:18,fixed"`
	Audit         int      `json:"audit,omitempty" column:"audit,minWidth:5"`
	Verdict       string   `json:"verdict,omitempty" column:"verdict,width:7,fixed"`
	InsetID       *bool    `json:"insetid,omitempty" column:"insetid,width:7,fixed,hide"`
	TargetUserNs  uint64   `json:"targetuserns,omitempty" column:"targetuserns,template:ns"`
	CurrentUserNs uint64   `json:"currentuserns,omitempty" column:"currentuserns,template:ns"`
	Caps          uint64   `json:"caps,omitempty" column:"caps,hide"`
	CapsNames     []string `json:"capsNames,omitempty" column:"capsnames,hide"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.SetExtractor("insetid", func(event *Event) (ret string) {
		if event.InsetID == nil {
			return "N/A"
		}

		return fmt.Sprintf("%t", *event.InsetID)
	})

	cols.MustSetExtractor("caps", func(event *Event) string {
		return fmt.Sprintf("%x", event.Caps)
	})

	cols.MustSetExtractor("capsnames", func(event *Event) string {
		return strings.Join(event.CapsNames, ",")
	})
	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

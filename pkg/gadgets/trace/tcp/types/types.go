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
	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Operation string `json:"operation,omitempty" column:"t,width:1,fixed"`
	Pid       uint32 `json:"pid,omitempty" column:"pid,width:7,fixed"`
	Comm      string `json:"comm,omitempty" column:"comm,width:16,fixed"`
	IPVersion int    `json:"ipversion,omitempty" column:"ip,width:2,fixed"`
	Saddr     string `json:"saddr,omitempty" column:"saddr,width:22"`
	Daddr     string `json:"daddr,omitempty" column:"daddr,width:22"`
	Sport     uint16 `json:"sport,omitempty" column:"sport,width:5,fixed"`
	Dport     uint16 `json:"dport,omitempty" column:"dport,width:5,fixed"`
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,width:12,hide"`
}

func GetColumns() *columns.Columns[Event] {
	execColumns := columns.MustCreateColumns[Event]()

	execColumns.MustSetExtractor("t", func(event *Event) (ret string) {
		operations := map[string]string{
			"accept":  "A",
			"connect": "C",
			"close":   "X",
			"unknown": "U",
		}

		if op, ok := operations[event.Operation]; ok {
			return op
		}

		return "U"
	})

	return execColumns
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}

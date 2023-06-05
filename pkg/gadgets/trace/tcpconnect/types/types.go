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
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid       uint32        `json:"pid,omitempty" column:"pid,template:pid"`
	Uid       uint32        `json:"uid" column:"uid,template:uid,hide"`
	Gid       uint32        `json:"gid" column:"gid,template:gid,hide"`
	Comm      string        `json:"comm,omitempty" column:"comm,template:comm"`
	IPVersion int           `json:"ipversion,omitempty" column:"ip,template:ipversion"`
	Saddr     string        `json:"saddr,omitempty" column:"saddr,template:ipaddr"`
	Daddr     string        `json:"daddr,omitempty" column:"daddr,template:ipaddr"`
	Sport     uint16        `json:"sport,omitempty" column:"sport,template:ipport"`
	Dport     uint16        `json:"dport,omitempty" column:"dport,template:ipport"`
	Latency   time.Duration `json:"latency,omitempty" column:"latency,minWidth:8,align:right" columnTags:"param:latency"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.MustSetExtractor("latency", func(event *Event) string {
		return event.Latency.String()
	})

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

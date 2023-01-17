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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	MinLatencyDefault = uint(10)
)

type Event struct {
	eventtypes.Event

	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,template:ns"`
	Pid       uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	Op        string `json:"op,omitempty" column:"T,width:1,fixed"`
	Bytes     uint64 `json:"bytes,omitempty" column:"bytes,width:10,align:right"`
	Offset    int64  `json:"offset,omitempty" column:"offset,width:10,align:right"`
	Latency   uint64 `json:"latency,omitempty" column:"lat,width:10,align:right"`
	File      string `json:"file,omitempty" column:"file,width:24,maxWidth:32"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

func (ev *Event) GetMountNSID() uint64 {
	return ev.MountNsID
}

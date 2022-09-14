// Copyright 2019-2022 The Inspektor Gadget authors
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

	Pid       uint32 `json:"pid,omitempty" column:"pid,width:7" columnDesc:"Process ID"`
	TargetPid uint32 `json:"tpid,omitempty" column:"tpid,width:7" columnDesc:"Target Process ID"`
	Signal    string `json:"signal,omitempty" column:"signal,width:16"`
	Retval    int    `json:"ret,omitempty" column:"ret,width:6" columnDesc:"Return Value"`
	Comm      string `json:"comm,omitempty" column:"comm,width:16" columnDesc:"Command"`
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,width:12,hide"`
}

var signalColumns = columns.MustCreateColumns[Event]()

func MustGetColumns() *columns.Columns[Event] {
	return signalColumns
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}

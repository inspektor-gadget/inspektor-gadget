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

	KilledPid     uint32 `json:"kpid,omitempty" column:"kpid,minWidth:7"`
	KilledComm    string `json:"kcomm,omitempty" column:"kcomm,maxWidth:16"`
	Pages         uint64 `json:"pages,omitempty" column:"pages,width:6"`
	TriggeredPid  uint32 `json:"tpid,omitempty" column:"tpid,minWidth:7"`
	TriggeredComm string `json:"tcomm,omitempty" column:"tcomm,maxWidth:16"`
	MountNsID     uint64 `json:"mountnsid,omitempty" column:"mntns,width:12,hide"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}

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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	KilledPid     uint32 `json:"kpid,omitempty" column:"kpid,template:pid"`
	KilledComm    string `json:"kcomm,omitempty" column:"kcomm,template:comm"`
	Pages         uint64 `json:"pages,omitempty" column:"pages,width:6"`
	TriggeredPid  uint32 `json:"tpid,omitempty" column:"tpid,template:pid"`
	TriggeredUid  uint32 `json:"tuid" column:"tuid,template:uid,hide"`
	TriggeredGid  uint32 `json:"tgid" column:"tgid,template:gid,hide"`
	TriggeredComm string `json:"tcomm,omitempty" column:"tcomm,template:comm"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

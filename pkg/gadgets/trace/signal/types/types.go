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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Pid  uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Comm string `json:"comm,omitempty" column:"comm,template:comm"`
	// The most common signals are SIGKILL, SIGTERM, SIGINT (6 chars) and the
	// longest is SIGRTMIN+XX (11 chars).
	Signal    string `json:"signal,omitempty" column:"signal,minWidth:6,maxWidth:11,ellipsis:start"`
	TargetPid uint32 `json:"tpid,omitempty" column:"tpid,template:pid"`
	Retval    int    `json:"ret,omitempty" column:"ret,width:3,fixed"`
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,template:ns"`
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

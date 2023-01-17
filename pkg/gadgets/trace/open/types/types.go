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

	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,width:12,hide"`
	Pid       uint32 `json:"pid,omitempty" column:"pid,minWidth:7"`
	UID       uint32 `json:"uid,omitempty" column:"uid,minWidth:10,hide"`
	Comm      string `json:"comm,omitempty" column:"comm,maxWidth:16"`
	Fd        int    `json:"fd,omitempty" column:"fd,minWidth:2,width:3"`
	Ret       int    `json:"ret,omitempty" column:"ret,width:3,fixed,hide"`
	Err       int    `json:"err,omitempty" column:"err,width:3,fixed"`
	Path      string `json:"path,omitempty" column:"path,minWidth:24,width:32"`
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

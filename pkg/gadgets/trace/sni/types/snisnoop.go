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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithNetNsID

	Pid  uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Tid  uint32 `json:"tid,omitempty" column:"tid,template:pid"`
	Comm string `json:"comm,omitempty" column:"comm,template:comm"`

	Uid uint32 `json:"uid" column:"uid,template:uid,hide"`
	Gid uint32 `json:"gid" column:"gid,template:gid,hide"`

	Name string `json:"name,omitempty" column:"name,width:30"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	// Hide container column for kubernetes environment
	if environment.Environment == environment.Kubernetes {
		col, _ := cols.GetColumn("k8s.container")
		col.Visible = false
	}

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

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

	Pid       uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Uid       uint32 `json:"uid" column:"uid,template:uid,hide"`
	Gid       uint32 `json:"gid" column:"gid,template:gid,hide"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	IPVersion int    `json:"ipversion,omitempty" column:"ip,template:ipversion"`

	SrcEndpoint eventtypes.L4Endpoint `json:"src,omitempty" column:"src"`
	DstEndpoint eventtypes.L4Endpoint `json:"dst,omitempty" column:"dst"`

	Latency time.Duration `json:"latency,omitempty" column:"latency,minWidth:8,align:right,order:4000" columnTags:"param:latency"`
}

func (e *Event) GetEndpoints() []*eventtypes.L3Endpoint {
	return []*eventtypes.L3Endpoint{&e.SrcEndpoint.L3Endpoint, &e.DstEndpoint.L3Endpoint}
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.MustSetExtractor("latency", func(event *Event) string {
		return event.Latency.String()
	})

	eventtypes.MustAddVirtualL4EndpointColumn(
		cols,
		columns.Attributes{
			Name:     "src",
			Visible:  true,
			Template: "ipaddrport",
			Order:    2000,
		},
		func(e *Event) eventtypes.L4Endpoint { return e.SrcEndpoint },
	)
	eventtypes.MustAddVirtualL4EndpointColumn(
		cols,
		columns.Attributes{
			Name:     "dst",
			Visible:  true,
			Template: "ipaddrport",
			Order:    3000,
		},
		func(e *Event) eventtypes.L4Endpoint { return e.DstEndpoint },
	)

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

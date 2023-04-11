// Copyright 2023 The Inspektor Gadget authors
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
	// Can't use eventtypes.Event because this gadget doesn't support filtering by containers

	// Timestamp in nanoseconds since January 1, 1970 UTC. An int64 is big
	// enough to represent time between the year 1678 and 2262.
	Timestamp eventtypes.Time `json:"timestamp,omitempty" column:"timestamp,template:timestamp,stringer"`

	// Type indicates the kind of this event
	Type eventtypes.EventType `json:"type"`

	// Message when Type is ERR, WARN, DEBUG or INFO
	Message string `json:"message,omitempty"`

	// Node where the event comes from
	Node string `json:"node,omitempty" column:"node,template:node" columnTags:"kubernetes"`

	Pid       uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	IPVersion int    `json:"ipversion,omitempty" column:"ip,width:2,fixed"`
	Saddr     string `json:"saddr,omitempty" column:"saddr,template:ipaddr"`
	Daddr     string `json:"daddr,omitempty" column:"daddr,template:ipaddr"`
	Sport     uint16 `json:"sport,omitempty" column:"sport,template:ipport"`
	Dport     uint16 `json:"dport,omitempty" column:"dport,template:ipport"`
	State     string `json:"state,omitempty" column:"state,minWidth:9,maxWidth:12"`
	Tcpflags  string `json:"tcpflags,omitempty" column:"tcpflags,minWidth:7,maxWidth:31"`
	Reason    string `json:"reason,omitempty" column:"reason,minWidth:14,maxWidth:23"`
}

// Implement the ErrorGetter interface. TODO: Remove once we use eventtypes.Event again.

func (ev *Event) GetType() eventtypes.EventType {
	return ev.Type
}

func (ev *Event) GetMessage() string {
	return ev.Message
}

func (ev *Event) SetNode(node string) {
	ev.Node = node
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Type:    ev.Type,
		Message: ev.Message,
	}
}

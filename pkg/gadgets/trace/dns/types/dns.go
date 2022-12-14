// Copyright 2019-2021 The Inspektor Gadget authors
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

type DNSPktType string

const (
	DNSPktTypeQuery    DNSPktType = "Q"
	DNSPktTypeResponse DNSPktType = "R"
)

type Event struct {
	eventtypes.Event

	Pid       uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Tid       uint32 `json:"tid,omitempty" column:"tid,template:pid"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,template:ns"`

	ID         string        `json:"id,omitempty" column:"id,width:4,fixed,hide"`
	Qr         DNSPktType    `json:"qr,omitempty" column:"qr,width:2,fixed"`
	Nameserver string        `json:"nameserver,omitempty" column:"nameserver,template:ipaddr"`
	PktType    string        `json:"pktType,omitempty" column:"type,minWidth:7,maxWidth:9"`
	QType      string        `json:"qtype,omitempty" column:"qtype,minWidth:5,maxWidth:10"`
	DNSName    string        `json:"name,omitempty" column:"name,width:30"`
	Rcode      string        `json:"rcode,omitempty" column:"rcode,minWidth:8"`
	Latency    time.Duration `json:"latency,omitempty" column:"latency,hide"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	col, _ := cols.GetColumn("container")
	col.Visible = false

	cols.MustSetExtractor("latency", func(event *Event) string {
		if event.Latency > 0 {
			return event.Latency.String()
		} else {
			// Latency is reported only for DNS responses, not queries.
			// Latency might not be set for responses if the lookup for the query timestamp failed,
			// either because the query was evicted or the DNS packet had an invalid ID.
			return ""
		}
	})

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

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
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type DNSPktType string

const (
	DNSPktTypeQuery    DNSPktType = "Q"
	DNSPktTypeResponse DNSPktType = "R"
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

	SrcIP    string `json:"srcIP,omitempty" column:"srcIP,template:ipaddr,hide"`
	DstIP    string `json:"dstIP,omitempty" column:"dstIP,template:ipaddr,hide"`
	SrcPort  uint16 `json:"srcPort,omitempty" column:"srcPort,template:ipport,hide"`
	DstPort  uint16 `json:"dstPort,omitempty" column:"dstPort,template:ipport,hide"`
	Protocol string `json:"protocol,omitempty" column:"proto,maxWidth:5,hide"`

	ID         string        `json:"id,omitempty" column:"id,width:4,fixed,hide"`
	Qr         DNSPktType    `json:"qr,omitempty" column:"qr,width:2,fixed"`
	Nameserver string        `json:"nameserver,omitempty" column:"nameserver,template:ipaddr,hide"`
	PktType    string        `json:"pktType,omitempty" column:"type,minWidth:7,maxWidth:9"`
	QType      string        `json:"qtype,omitempty" column:"qtype,minWidth:5,maxWidth:10"`
	DNSName    string        `json:"name,omitempty" column:"name,width:30"`
	Rcode      string        `json:"rcode,omitempty" column:"rcode,minWidth:8"`
	Latency    time.Duration `json:"latency,omitempty" column:"latency,hide"`
	NumAnswers int           `json:"numAnswers,omitempty" column:"numAnswers,width:8,maxWidth:8" columnDesc:"Number of addresses contained in the response."`
	Addresses  []string      `json:"addresses,omitempty" column:"addresses,width:32,hide" columnDesc:"Addresses in the response. Maximum 8 are reported. Only available if the response is compressed."`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	// Hide container column for kubernetes environment
	if environment.Environment == environment.Kubernetes {
		col, _ := cols.GetColumn("k8s.container")
		col.Visible = false
	}

	optional := []string{"srcIP", "dstIP", "srcPort", "dstPort", "protocol"}
	for _, name := range optional {
		if col, ok := cols.GetColumn(name); ok {
			col.Visible = false
		}
	}

	cols.MustSetExtractor("latency", func(event *Event) any {
		if event.Latency > 0 {
			return event.Latency.String()
		} else {
			// Latency is reported only for DNS responses, not queries.
			// Latency might not be set for responses if the lookup for the query timestamp failed,
			// either because the query was evicted or the DNS packet had an invalid ID.
			return ""
		}
	})

	cols.MustSetExtractor("addresses", func(event *Event) any {
		return strings.Join(event.Addresses, ",")
	})

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

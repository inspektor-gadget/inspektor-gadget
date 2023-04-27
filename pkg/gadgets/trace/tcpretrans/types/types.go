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
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithNetNsID

	Pid  uint32 `json:"pid,omitempty" column:"pid,template:pid,order:1000"`
	Comm string `json:"comm,omitempty" column:"comm,template:comm,order:1001"`

	IPVersion int `json:"ipversion,omitempty" column:"ip,width:2,fixed,order:1005"`

	Saddr string `json:"saddr,omitempty" column:"saddr,template:ipaddr,hide,order:2001"`
	Sport uint16 `json:"sport,omitempty" column:"sport,template:ipport,hide,order:2002"`

	Daddr string `json:"daddr,omitempty" column:"daddr,template:ipaddr,hide,order:3001"`
	Dport uint16 `json:"dport,omitempty" column:"dport,template:ipport,hide,order:3002"`

	State    string `json:"state,omitempty" column:"state,minWidth:9,maxWidth:12,order:5000"`
	Tcpflags string `json:"tcpflags,omitempty" column:"tcpflags,minWidth:7,maxWidth:31,order:5001"`

	/* Source IP resolved by kubeipresolver  */
	SrcKind      eventtypes.RemoteKind `json:"srcKind,omitempty" column:"srcKind,maxWidth:5,hide,order:2100"`
	SrcNamespace string                `json:"srcNamespace,omitempty" column:"srcns,hide,order:2101"`
	SrcName      string                `json:"srcName,omitempty" column:"srcname,hide,order:2102"`

	/* Destination IP resolved by kubeipresolver  */
	DstKind      eventtypes.RemoteKind `json:"dstKind,omitempty" column:"dstKind,maxWidth:5,hide,order:3100"`
	DstNamespace string                `json:"dstNamespace,omitempty" column:"dstns,hide,order:3101"`
	DstName      string                `json:"dstName,omitempty" column:"dstname,hide,order:3102"`
}

func (e *Event) SetLocalPodDetails(owner, hostIP, podIP string, labels map[string]string) {
	// Unused
}

func (e *Event) GetRemoteIPs() []string {
	return []string{e.Saddr, e.Daddr}
}

func (e *Event) SetEndpointsDetails(endpoints []eventtypes.EndpointDetails) {
	if len(endpoints) != 2 {
		return
	}
	e.SrcName = endpoints[0].Name
	e.SrcNamespace = endpoints[0].Namespace
	e.SrcKind = endpoints[0].Kind

	e.DstName = endpoints[1].Name
	e.DstNamespace = endpoints[1].Namespace
	e.DstKind = endpoints[1].Kind
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	// Virtual column for the source and destination endpoints
	err := cols.AddColumn(columns.Column[Event]{
		Name: "src",
		Extractor: func(e *Event) string {
			switch e.SrcKind {
			case eventtypes.RemoteKindPod:
				return "p/" + e.SrcNamespace + "/" + e.SrcName + ":" + fmt.Sprint(e.Sport)
			case eventtypes.RemoteKindService:
				return "s/" + e.SrcNamespace + "/" + e.SrcName + ":" + fmt.Sprint(e.Sport)
			case eventtypes.RemoteKindOther:
				return "o/" + e.Saddr + ":" + fmt.Sprint(e.Sport)
			}
			return e.Saddr + ":" + fmt.Sprint(e.Sport)
		},
		Visible: true,
		Width:   30,
		Order:   2000,
	})
	if err != nil {
		panic(err)
	}
	err = cols.AddColumn(columns.Column[Event]{
		Name: "dst",
		Extractor: func(e *Event) string {
			switch e.DstKind {
			case eventtypes.RemoteKindPod:
				return "p/" + e.DstNamespace + "/" + e.DstName + ":" + fmt.Sprint(e.Dport)
			case eventtypes.RemoteKindService:
				return "s/" + e.DstNamespace + "/" + e.DstName + ":" + fmt.Sprint(e.Dport)
			case eventtypes.RemoteKindOther:
				return "o/" + e.Daddr + ":" + fmt.Sprint(e.Dport)
			}
			return e.Daddr + ":" + fmt.Sprint(e.Dport)
		},
		Visible: true,
		Width:   30,
		Order:   3000,
	})
	if err != nil {
		panic(err)
	}

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

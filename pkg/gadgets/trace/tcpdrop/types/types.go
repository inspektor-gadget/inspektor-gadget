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
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithNetNsID

	Pid       uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	IPVersion int    `json:"ipversion,omitempty" column:"ip,width:2,fixed"`

	Saddr string `json:"saddr,omitempty" column:"saddr,template:ipaddr"`
	Daddr string `json:"daddr,omitempty" column:"daddr,template:ipaddr"`

	Sport    uint16 `json:"sport,omitempty" column:"sport,template:ipport"`
	Dport    uint16 `json:"dport,omitempty" column:"dport,template:ipport"`
	State    string `json:"state,omitempty" column:"state,minWidth:9,maxWidth:12"`
	Tcpflags string `json:"tcpflags,omitempty" column:"tcpflags,minWidth:7,maxWidth:31"`
	Reason   string `json:"reason,omitempty" column:"reason,minWidth:14,maxWidth:23"`

	/* Source IP resolved by kubeipresolver  */
	SrcKind      eventtypes.RemoteKind `json:"srcKind,omitempty" column:"srcKind,maxWidth:5"`
	SrcNamespace string                `json:"srcNamespace,omitempty" column:"srcns"`
	SrcName      string                `json:"srcName,omitempty" column:"srcname"`

	/* Destination IP resolved by kubeipresolver  */
	DstKind      eventtypes.RemoteKind `json:"dstKind,omitempty" column:"dstKind,maxWidth:5"`
	DstNamespace string                `json:"dstNamespace,omitempty" column:"dstns"`
	DstName      string                `json:"dstName,omitempty" column:"dstname"`
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
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

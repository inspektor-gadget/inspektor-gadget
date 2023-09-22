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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
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

	PktType string `json:"pktType,omitempty" column:"type,maxWidth:9"`
	Proto   string `json:"proto,omitempty" column:"proto,maxWidth:5"`
	Port    uint16 `json:"port,omitempty" column:"port,template:ipport"`

	/* Further information of pod where event occurs */
	PodHostIP string            `json:"podHostIP,omitempty" column:"podhostip,template:ipaddr,hide"`
	PodIP     string            `json:"podIP,omitempty" column:"podip,template:ipaddr,hide"`
	PodOwner  string            `json:"podOwner,omitempty" column:"podowner,hide"`
	PodLabels map[string]string `json:"podLabels,omitempty" column:"podlabels,hide"`

	DstEndpoint eventtypes.L3Endpoint `json:"dst,omitempty" column:"dst"`
}

func (e *Event) SetLocalPodDetails(owner, hostIP, podIP string, labels map[string]string) {
	e.PodOwner = owner
	e.PodHostIP = hostIP
	e.PodIP = podIP
	e.PodLabels = labels
}

func (e *Event) GetEndpoints() []*eventtypes.L3Endpoint {
	return []*eventtypes.L3Endpoint{&e.DstEndpoint}
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	eventtypes.MustAddVirtualL3EndpointColumn(
		cols,
		columns.Attributes{
			Name:         "remote",
			Width:        32,
			MinWidth:     21,
			Visible:      true,
			Order:        1000,
			EllipsisType: ellipsis.Start,
		},
		func(e *Event) eventtypes.L3Endpoint { return e.DstEndpoint })

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

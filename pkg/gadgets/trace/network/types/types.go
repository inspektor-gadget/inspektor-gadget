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
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type RemoteKind string

const (
	RemoteKindPod     RemoteKind = "pod"
	RemoteKindService RemoteKind = "svc"
	RemoteKindOther   RemoteKind = "other"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithNetNsID

	PktType string `json:"pktType,omitempty" column:"type,maxWidth:9"`
	Proto   string `json:"proto,omitempty" column:"proto,maxWidth:5"`
	Port    uint16 `json:"port,omitempty" column:"port,template:ipport"`

	/* Further information of pod where event occurs */
	PodHostIP string            `json:"podHostIP,omitempty" column:"podhostip,template:ipaddr,hide"`
	PodIP     string            `json:"podIP,omitempty" column:"podip,template:ipaddr,hide"`
	PodOwner  string            `json:"podOwner,omitempty" column:"podowner,hide"`
	PodLabels map[string]string `json:"podLabels,omitempty" column:"podlabels,hide"`

	/* Remote */
	RemoteKind RemoteKind `json:"remoteKind,omitempty" column:"remoteKind,maxWidth:5,hide"`
	RemoteAddr string     `json:"remoteAddr,omitempty" column:"remoteAddr,template:ipaddr,hide"`

	/* if RemoteKind = RemoteKindPod or RemoteKindService */
	RemoteName      string            `json:"remoteName,omitempty" column:"remotename,hide"`
	RemoteNamespace string            `json:"remoteNamespace,omitempty" column:"remotens,hide"`
	RemoteLabels    map[string]string `json:"remoteLabels,omitempty" column:"remotelabels,hide"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	cols.MustAddColumn(columns.Column[Event]{
		Name:         "remote",
		Width:        32,
		MinWidth:     21,
		Visible:      true,
		Order:        1000,
		EllipsisType: ellipsis.Start,
		Extractor: func(e *Event) string {
			switch e.RemoteKind {
			case RemoteKindPod:
				return fmt.Sprintf("pod %s/%s", e.RemoteNamespace, e.RemoteName)
			case RemoteKindService:
				return fmt.Sprintf("svc %s/%s", e.RemoteNamespace, e.RemoteName)
			case RemoteKindOther:
				return fmt.Sprintf("endpoint %s", e.RemoteAddr)
			default:
				return e.RemoteAddr
			}
		},
	})

	// Hide container column for kubernetes environment
	if environment.Environment == environment.Kubernetes {
		col, _ := cols.GetColumn("container")
		col.Visible = false
	}

	return cols
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

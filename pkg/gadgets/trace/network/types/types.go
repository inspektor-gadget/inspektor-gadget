// Copyright 2022 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
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

	PktType string `json:"pktType,omitempty" column:"type,maxWidth:9"`
	Proto   string `json:"proto,omitempty" column:"proto,maxWidth:5"`
	Addr    string `json:"addr,omitempty" column:"addr,template:ipaddr,hide"`
	Port    uint16 `json:"port,omitempty" column:"port,template:ipport"`

	/* Further information of pod where event occurs */
	PodHostIP string            `json:"podHostIP,omitempty" column:"podhostip,template:ipaddr,hide"`
	PodIP     string            `json:"podIP,omitempty" column:"podip,template:ipaddr,hide"`
	PodOwner  string            `json:"podOwner,omitempty" column:"podowner,hide"`
	PodLabels map[string]string `json:"podLabels,omitempty" column:"padlabels,hide"`

	/* Remote */
	RemoteKind RemoteKind `json:"remoteKind,omitempty" column:"kind,maxWidth:5"`

	/* if RemoteKind = RemoteKindPod or RemoteKindService */
	RemoteName      string            `json:"remoteName,omitempty" column:"remotename,hide"`
	RemoteNamespace string            `json:"remoteNamespace,omitempty" column:"remotens,hide"`
	RemoteLabels    map[string]string `json:"remoteLabels,omitempty" column:"remotelabels,hide"`

	/* if RemoteKind = RemoteKindOther */
	RemoteOther string `json:"remoteOther,omitempty" column:"remoteother,template:ipaddr,hide"`
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
				return fmt.Sprintf("endpoint %s", e.RemoteOther)
			default:
				return "unknown"
			}
		},
	})

	col, _ := cols.GetColumn("container")
	col.Visible = false

	return cols
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}

func Unique(edges []Event) []Event {
	keys := make(map[string]bool)
	list := []Event{}
	for _, e := range edges {
		key := e.Key()
		if _, value := keys[key]; !value {
			keys[key] = true
			list = append(list, e)
		}
	}
	return list
}

func (e *Event) Key() string {
	return fmt.Sprintf("%s/%s/%s/%s/%s/%d",
		e.Namespace,
		e.Pod,
		e.PktType,
		e.Proto,
		e.Addr,
		e.Port)
}

func EventsString(edges []Event) string {
	b, err := json.Marshal(edges)
	if err != nil {
		return fmt.Sprintf("error marshalling event: %s\n", err)
	}
	return string(b)
}

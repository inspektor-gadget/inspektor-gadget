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

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	PktType string `json:"pkt_type,omitempty"`
	Proto   string `json:"proto,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`

	/* pod, svc or other */
	RemoteKind string `json:"remote_kind,omitempty"`

	PodHostIP string            `json:"pod_host_ip,omitempty"`
	PodIP     string            `json:"pod_ip,omitempty"`
	PodOwner  string            `json:"pod_owner,omitempty"`
	PodLabels map[string]string `json:"pod_labels,omitempty"`

	/* if RemoteKind = svc */
	RemoteSvcNamespace     string            `json:"remote_svc_namespace,omitempty"`
	RemoteSvcName          string            `json:"remote_svc_name,omitempty"`
	RemoteSvcLabelSelector map[string]string `json:"remote_svc_label_selector,omitempty"`

	/* if RemoteKind = pod */
	RemotePodNamespace string            `json:"remote_pod_namespace,omitempty"`
	RemotePodName      string            `json:"remote_pod_name,omitempty"`
	RemotePodLabels    map[string]string `json:"remote_pod_labels,omitempty"`

	/* if RemoteKind = other */
	RemoteOther string `json:"remote_other,omitempty"`

	Debug string `json:"debug,omitempty"`
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
		e.IP,
		e.Port)
}

func EventsString(edges []Event) string {
	b, err := json.Marshal(edges)
	if err != nil {
		return fmt.Sprintf("error marshalling event: %s\n", err)
	}
	return string(b)
}

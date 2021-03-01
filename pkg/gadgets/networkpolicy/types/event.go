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

type KubernetesConnectionEvent struct {
	/* "ready", or "connect" or "accept" */
	Type string `json:"type"`

	/* pod, svc or other */
	RemoteKind string `json:"remote_kind"`

	/* Port */
	Port uint16 `json:"port"`

	LocalPodNamespace string            `json:"local_pod_namespace"`
	LocalPodName      string            `json:"local_pod_name"`
	LocalPodOwner     string            `json:"local_pod_owner,omitempty"`
	LocalPodLabels    map[string]string `json:"local_pod_labels"`

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

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

type Event struct {
	// Err is a fatal error; clients should stop parsing
	Err string `json:"err,omitempty"`

	// Notice is additional information to be displayed with 'verbose'
	// option
	Notice string `json:"notice,omitempty"`

	// Ready should be sent only once per node
	Ready bool `json:"ready,omitempty"`

	// Node where the event comes from
	Node string `json:"node,omitempty"`

	// Host if the event comes from the host
	Host bool `json:"host,omitempty"`

	// Pod namespace where the event comes from, or empty for host-level
	// event
	Namespace string `json:"namespace,omitempty"`

	// Pod where the event comes from, or empty for host-level event
	Pod string `json:"pod,omitempty"`

	// Container where the event comes from, or empty for host-level or
	// pod-level event
	Container string `json:"contaienr,omitempty"`
}

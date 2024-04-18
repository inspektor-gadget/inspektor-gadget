// Copyright 2023-2024 The Inspektor Gadget authors
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
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type L3Endpoint struct {
	eventtypes.L3Endpoint
	Name string
}

type L4Endpoint struct {
	eventtypes.L4Endpoint
	Name string
}

type Event struct {
	// Do not use eventtypes.Event because we don't want to have the timestamp column.
	eventtypes.CommonData

	// Type indicates the kind of this event
	Type eventtypes.EventType `json:"type"`

	// Message when Type is ERR, WARN, DEBUG or INFO
	Message string `json:"message,omitempty"`

	L3Endpoints []L3Endpoint      `json:"l3endpoints,omitempty"`
	L4Endpoints []L4Endpoint      `json:"l4endpoints,omitempty"`
	Timestamps  []eventtypes.Time `json:"timestamps,omitempty"`

	MountNsID uint64 `json:"-"`
	NetNsID   uint64 `json:"-"`

	// Blob is used to save data to be sent to the client.
	// [0] is used for bpf event
	// [1] is used for fixed-size members
	// [1+] is used for variable size members
	Blob [][]byte `json:"blob,omitempty"`
}

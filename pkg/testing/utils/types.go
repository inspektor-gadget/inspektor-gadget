// Copyright 2024 The Inspektor Gadget authors
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

package utils

import (
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Define some types that are only used for testing purposes

type K8s struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Labels    string `json:"labels"`
}

type L4Endpoint struct {
	Addr    string `json:"addr"`
	Version uint8  `json:"version"`
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	K8s     K8s    `json:"k8s"`
}

type L3Endpoint struct {
	Addr    string `json:"addr"`
	Version uint8  `json:"version"`
}

type (
	Creds   = ebpftypes.Creds
	Parent  = ebpftypes.Parent
	Process = ebpftypes.Process
)

type CommonData = eventtypes.CommonData

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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	IndexVirtual = -1
	IndexEBPF    = 0
	IndexFixed   = 1
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

func (ev *Event) GetMountNSID() uint64 {
	return ev.MountNsID
}

func (ev *Event) GetNetNSID() uint64 {
	return ev.NetNsID
}

func (ev *Event) GetEndpoints() []*eventtypes.L3Endpoint {
	endpoints := make([]*eventtypes.L3Endpoint, 0, len(ev.L3Endpoints)+len(ev.L4Endpoints))

	for i := range ev.L3Endpoints {
		endpoints = append(endpoints, &ev.L3Endpoints[i].L3Endpoint)
	}
	for i := range ev.L4Endpoints {
		endpoints = append(endpoints, &ev.L4Endpoints[i].L3Endpoint)
	}

	return endpoints
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

// Printer is implemented by objects that can print information, like frontends.
type Printer interface {
	Output(payload string)
	Logf(severity logger.Level, fmt string, params ...any)
}

type Kind uint8

// TODO: use reflect.Kind? (once we resolve TODO below)
const (
	KindNone Kind = iota
	KindUint8
	KindUint16
	KindUint32
	KindUint64
	KindInt8
	KindInt16
	KindInt32
	KindInt64
	KindBool
	KindFloat32
	KindFloat64
	KindString
	KindArray

	// TODO: this should be made more generic to avoid coupling operators with this
	KindL3Endpoint
	KindL4Endpoint
	KindTimestamp
)

type Type struct {
	Kind Kind

	// Fields only for KindArray
	ArrayNElements int // number of elements in the array
	ArrayType      *Type
}

// ColumnDesc describes how a column is built. It's basically a serializable version of
// columns.DynamicField
type ColumnDesc struct {
	Name      string
	BlobIndex int // -1: virtual, 0: ebpf, 1: fixed length, 1+ strings
	Type      Type
	Offset    uintptr
}

type GadgetInfo struct {
	GadgetMetadata *metadatav1.GadgetMetadata
	Columns        []ColumnDesc
	ProgContent    []byte
	GadgetType     gadgets.GadgetType
	EventFactory   *EventFactory
}

// RunGadgetDesc represents the different methods implemented by the run gadget descriptor.
type RunGadgetDesc interface {
	GetGadgetInfo(params *params.Params, args []string) (*GadgetInfo, error)
	CustomParser(info *GadgetInfo) (parser.Parser, error)
	JSONConverter(info *GadgetInfo, p Printer) func(ev any)
	JSONPrettyConverter(info *GadgetInfo, p Printer) func(ev any)
	YAMLConverter(info *GadgetInfo, p Printer) func(ev any)
}

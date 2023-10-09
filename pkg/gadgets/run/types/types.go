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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	ValidateMetadataParam = "validate-metadata"
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
	eventtypes.Event
	eventtypes.WithMountNsID

	L3Endpoints []L3Endpoint `json:"l3endpoints,omitempty"`
	L4Endpoints []L4Endpoint `json:"l4endpoints,omitempty"`

	// Raw event sent by the ebpf program
	RawData []byte `json:"raw_data,omitempty"`
}

type GadgetInfo struct {
	GadgetMetadata *GadgetMetadata
	ProgContent    []byte
	GadgetType     gadgets.GadgetType
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

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}

// Printer is implemented by objects that can print information, like frontends.
type Printer interface {
	Output(payload string)
	Logf(severity logger.Level, fmt string, params ...any)
}

// RunGadgetDesc represents the different methods implemented by the run gadget descriptor.
type RunGadgetDesc interface {
	GetGadgetInfo(params *params.Params, args []string) (*GadgetInfo, error)
	CustomParser(info *GadgetInfo) (parser.Parser, error)
	JSONConverter(info *GadgetInfo, p Printer) func(ev any)
	JSONPrettyConverter(info *GadgetInfo, p Printer) func(ev any)
	YAMLConverter(info *GadgetInfo, p Printer) func(ev any)
}

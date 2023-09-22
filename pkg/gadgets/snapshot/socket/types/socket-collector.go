// Copyright 2021-2023 The Inspektor Gadget authors
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
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Proto int

const (
	INVALID Proto = iota
	ALL
	TCP
	UDP
)

var ProtocolsMap = map[string]Proto{
	"all": ALL,
	"tcp": TCP,
	"udp": UDP,
}

type Event struct {
	eventtypes.Event
	eventtypes.WithNetNsID

	Protocol    string                `json:"protocol" column:"protocol,maxWidth:8"`
	SrcEndpoint eventtypes.L4Endpoint `json:"src,omitempty" column:"src"`
	DstEndpoint eventtypes.L4Endpoint `json:"dst,omitempty" column:"dst"`
	Status      string                `json:"status" column:"status,order:1002,maxWidth:12"`
	InodeNumber uint64                `json:"inodeNumber" column:"inode,order:1003,hide"`
}

func (e *Event) GetEndpoints() []*eventtypes.L3Endpoint {
	return []*eventtypes.L3Endpoint{&e.SrcEndpoint.L3Endpoint, &e.DstEndpoint.L3Endpoint}
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	// Hide container column for kubernetes environment
	if environment.Environment == environment.Kubernetes {
		col, _ := cols.GetColumn("k8s.container")
		col.Visible = false
	}

	eventtypes.MustAddVirtualL4EndpointColumn(
		cols,
		columns.Attributes{
			Name:     "src",
			Visible:  true,
			Template: "ipaddrport",
			Order:    1000,
		},
		func(e *Event) eventtypes.L4Endpoint { return e.SrcEndpoint },
	)
	eventtypes.MustAddVirtualL4EndpointColumn(
		cols,
		columns.Attributes{
			Name:     "dst",
			Visible:  true,
			Template: "ipaddrport",
			Order:    1001,
		},
		func(e *Event) eventtypes.L4Endpoint { return e.DstEndpoint },
	)

	return cols
}

func ParseProtocol(protocol string) (Proto, error) {
	if r, ok := ProtocolsMap[strings.ToLower(protocol)]; ok {
		return r, nil
	}

	return INVALID, fmt.Errorf("%q is not a valid protocol value", protocol)
}

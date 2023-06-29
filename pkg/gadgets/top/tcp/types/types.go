// Copyright 2019-2023 The Inspektor Gadget authors
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
	"syscall"

	"github.com/docker/go-units"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var SortByDefault = []string{"-sent", "-recv"}

const (
	PidParam    = "pid"
	FamilyParam = "family"
)

func ParseFilterByFamily(family string) (int32, error) {
	switch family {
	case "4":
		return syscall.AF_INET, nil
	case "6":
		return syscall.AF_INET6, nil
	default:
		return -1, fmt.Errorf("IP version is either 4 or 6, %s was given", family)
	}
}

// Stats represents the operations performed on a single file
type Stats struct {
	eventtypes.CommonData
	eventtypes.WithMountNsID

	Pid       int32  `json:"pid,omitempty" column:"pid,template:pid"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	IPVersion uint16 `json:"ipversion,omitempty" column:"ip,template:ipversion"`

	SrcEndpoint eventtypes.L4Endpoint `json:"src,omitempty" column:"src"`
	DstEndpoint eventtypes.L4Endpoint `json:"dst,omitempty" column:"dst"`

	Sent     uint64 `json:"sent,omitempty" column:"sent,order:1002"`
	Received uint64 `json:"received,omitempty" column:"recv,order:1003"`
}

func (e *Stats) GetEndpoints() []*eventtypes.L3Endpoint {
	return []*eventtypes.L3Endpoint{&e.SrcEndpoint.L3Endpoint, &e.DstEndpoint.L3Endpoint}
}

func GetColumns() *columns.Columns[Stats] {
	cols := columns.MustCreateColumns[Stats]()

	cols.MustSetExtractor("ip", func(stats *Stats) (ret string) {
		if stats.IPVersion == syscall.AF_INET {
			return "4"
		}
		return "6"
	})
	cols.MustSetExtractor("sent", func(stats *Stats) (ret string) {
		return fmt.Sprint(units.BytesSize(float64(stats.Sent)))
	})
	cols.MustSetExtractor("recv", func(stats *Stats) (ret string) {
		return fmt.Sprint(units.BytesSize(float64(stats.Received)))
	})

	eventtypes.MustAddVirtualL4EndpointColumn(
		cols,
		columns.Attributes{
			Name:     "src",
			Visible:  true,
			Template: "ipaddrport",
			Order:    1000,
		},
		func(s *Stats) eventtypes.L4Endpoint { return s.SrcEndpoint },
	)
	eventtypes.MustAddVirtualL4EndpointColumn(
		cols,
		columns.Attributes{
			Name:     "dst",
			Visible:  true,
			Template: "ipaddrport",
			Order:    1001,
		},
		func(s *Stats) eventtypes.L4Endpoint { return s.DstEndpoint },
	)

	return cols
}

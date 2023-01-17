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

	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,template:ns,hide"`
	Pid       int32  `json:"pid,omitempty" column:"pid,template:pid"`
	Comm      string `json:"comm,omitempty" column:"comm,template:comm"`
	Family    uint16 `json:"family,omitempty" column:"ip,maxWidth:2"`
	Saddr     string `json:"saddr,omitempty" column:"saddr,template:ipaddr,hide"`
	Daddr     string `json:"daddr,omitempty" column:"daddr,template:ipaddr,hide"`
	Sport     uint16 `json:"sport,omitempty" column:"sport,template:ipport,hide"`
	Dport     uint16 `json:"dport,omitempty" column:"dport,template:ipport,hide"`
	Sent      uint64 `json:"sent,omitempty" column:"sent,order:1002"`
	Received  uint64 `json:"received,omitempty" column:"recv,order:1003"`
}

func GetColumns() *columns.Columns[Stats] {
	cols := columns.MustCreateColumns[Stats]()

	cols.MustSetExtractor("ip", func(stats *Stats) (ret string) {
		if stats.Family == syscall.AF_INET {
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

	cols.MustAddColumn(columns.Column[Stats]{
		Name:     "local",
		MinWidth: 21, // 15(ipv4) + 1(:) + 5(port)
		MaxWidth: 51, // 45(ipv4 mapped ipv6) + 1(:) + 5(port)
		Visible:  true,
		Order:    1000,
		Extractor: func(s *Stats) string {
			return fmt.Sprintf("%s:%d", s.Saddr, s.Sport)
		},
	})
	cols.MustAddColumn(columns.Column[Stats]{
		Name:     "remote",
		MinWidth: 21, // 15(ipv4) + 1(:) + 5(port)
		MaxWidth: 51, // 45(ipv4 mapped ipv6) + 1(:) + 5(port)
		Visible:  true,
		Order:    1000,
		Extractor: func(s *Stats) string {
			return fmt.Sprintf("%s:%d", s.Daddr, s.Dport)
		},
	})

	return cols
}

func (ev *Stats) GetMountNSID() uint64 {
	return ev.MountNsID
}

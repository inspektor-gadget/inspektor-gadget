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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var SortByDefault = []string{"-sent", "-received"}

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

	Saddr     string `json:"saddr,omitempty" column:"saddr"`
	Daddr     string `json:"daddr,omitempty" column:"daddr"`
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns"`
	Pid       int32  `json:"pid,omitempty" column:"pid"`
	Comm      string `json:"comm,omitempty" column:"comm"`
	Sport     uint16 `json:"sport,omitempty" column:"sport"`
	Dport     uint16 `json:"dport,omitempty" column:"dport"`
	Family    uint16 `json:"family,omitempty" column:"family"`
	Sent      uint64 `json:"sent,omitempty" column:"sent"`
	Received  uint64 `json:"received,omitempty" column:"received"`
}

func GetColumns() *columns.Columns[Stats] {
	return columns.MustCreateColumns[Stats]()
}

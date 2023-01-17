// Copyright 2019-2022 The Inspektor Gadget authors
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
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type SortBy int

const (
	ALL SortBy = iota
	IO
	BYTES
	TIME
)

var SortByDefault = []string{"-ops", "-bytes", "-time"}

// Stats represents the operations performed on a single file
type Stats struct {
	eventtypes.CommonData

	Pid        int32  `json:"pid,omitempty" column:"pid"`
	Comm       string `json:"comm,omitempty" column:"comm"`
	Write      bool   `json:"write,omitempty" column:"r/w,maxWidth:3"`
	Major      int    `json:"major,omitempty" column:"major"`
	Minor      int    `json:"minor,omitempty" column:"minor"`
	Bytes      uint64 `json:"bytes,omitempty" column:"bytes"`
	MicroSecs  uint64 `json:"us,omitempty" column:"time"`
	Operations uint32 `json:"ops,omitempty" column:"ops"`
	MountNsID  uint64 `json:"mountnsid,omitempty" column:"mountnsid,template:ns,hide"`
}

func (ev *Stats) GetMountNSID() uint64 {
	return ev.MountNsID
}

func GetColumns() *columns.Columns[Stats] {
	cols := columns.MustCreateColumns[Stats]()

	cols.MustSetExtractor("r/w", func(stats *Stats) (ret string) {
		if stats.Write {
			return "W"
		}
		return "R"
	})

	return cols
}

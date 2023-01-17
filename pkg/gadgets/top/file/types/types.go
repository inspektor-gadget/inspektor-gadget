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

	"github.com/docker/go-units"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	AllFilesDefault = false
)

var SortByDefault = []string{"-reads", "-writes", "-rbytes", "-wbytes"}

const (
	AllFilesParam = "all-files"
)

// Stats represents the operations performed on a single file
type Stats struct {
	eventtypes.CommonData
	eventtypes.WithMountNsID

	Pid        uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	Tid        uint32 `json:"tid,omitempty" column:"tid,template:pid,hide"`
	Comm       string `json:"comm,omitempty" column:"comm,template:comm"`
	Reads      uint64 `json:"reads,omitempty" column:"reads"`
	Writes     uint64 `json:"writes,omitempty" column:"writes"`
	ReadBytes  uint64 `json:"rbytes,omitempty" column:"rbytes"`
	WriteBytes uint64 `json:"wbytes,omitempty" column:"wbytes"`
	FileType   byte   `json:"fileType,omitempty" column:"T,maxWidth:1"` // R = Regular File, S = Socket, O = Other
	Filename   string `json:"filename,omitempty" column:"file"`
}

func GetColumns() *columns.Columns[Stats] {
	cols := columns.MustCreateColumns[Stats]()

	cols.MustSetExtractor("rbytes", func(stats *Stats) (ret string) {
		return fmt.Sprint(units.BytesSize(float64(stats.ReadBytes)))
	})
	cols.MustSetExtractor("wbytes", func(stats *Stats) (ret string) {
		return fmt.Sprint(units.BytesSize(float64(stats.WriteBytes)))
	})
	cols.MustSetExtractor("T", func(stats *Stats) (ret string) {
		return string(stats.FileType)
	})

	return cols
}

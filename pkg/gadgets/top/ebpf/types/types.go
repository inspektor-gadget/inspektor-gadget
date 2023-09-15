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
	"fmt"
	"strings"
	"time"

	"github.com/docker/go-units"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var SortByDefault = []string{"-runtime", "-runcount"}

type Process struct {
	Pid  uint32 `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

type Stats struct {
	eventtypes.CommonData
	ProgramID          uint32     `json:"progid" column:"progid"`
	Type               string     `json:"type,omitempty" column:"type"`
	Name               string     `json:"name,omitempty" column:"name"`
	Processes          []*Process `json:"processes,omitempty"`
	CurrentRuntime     int64      `json:"currentRuntime,omitempty" column:"runtime,order:1001,align:right"`
	CurrentRunCount    uint64     `json:"currentRunCount,omitempty" column:"runcount,order:1002,width:10"`
	CumulativeRuntime  int64      `json:"cumulRuntime,omitempty" column:"cumulruntime,order:1003,hide"`
	CumulativeRunCount uint64     `json:"cumulRunCount,omitempty" column:"cumulruncount,order:1004,hide"`
	TotalRuntime       int64      `json:"totalRuntime,omitempty" column:"totalruntime,order:1005,align:right,hide"`
	TotalRunCount      uint64     `json:"totalRunCount,omitempty" column:"totalRunCount,order:1006,align:right,hide"`
	MapMemory          uint64     `json:"mapMemory,omitempty" column:"mapmemory,order:1007,align:right"`
	MapCount           uint32     `json:"mapCount,omitempty" column:"mapcount,order:1008"`
	TotalCpuUsage      float64    `json:"totalCpuUsage,omitempty" column:"totalcpu,order:1009,align:right,hide,precision:4"`
	PerCpuUsage        float64    `json:"perCpuUsage,omitempty" column:"percpu,order:1010,align:right,hide,precision:4"`
}

func GetColumns() *columns.Columns[Stats] {
	cols := columns.MustCreateColumns[Stats]()

	col, _ := cols.GetColumn("k8s.namespace")
	col.Visible = false
	col, _ = cols.GetColumn("k8s.pod")
	col.Visible = false
	col, _ = cols.GetColumn("k8s.container")
	col.Visible = false
	col, _ = cols.GetColumn("runtime.containerName")
	col.Visible = false

	cols.MustAddColumn(columns.Attributes{
		Name:         "pid",
		Width:        16,
		EllipsisType: ellipsis.End,
		Visible:      true,
		Order:        999,
	}, func(stats *Stats) any {
		pids := []string{}

		for _, pid := range stats.Processes {
			pids = append(pids, fmt.Sprint(pid.Pid))
		}

		return strings.Join(pids, ",")
	})

	cols.MustAddColumn(columns.Attributes{
		Name:         "comm",
		Width:        16,
		EllipsisType: ellipsis.End,
		Visible:      true,
		Order:        1000,
	}, func(stats *Stats) any {
		comms := []string{}

		for _, comm := range stats.Processes {
			comms = append(comms, comm.Comm)
		}

		return strings.Join(comms, ",")
	})
	cols.MustSetExtractor("runtime", func(stats *Stats) any {
		return fmt.Sprint(time.Duration(stats.CurrentRuntime))
	})
	cols.MustSetExtractor("totalruntime", func(stats *Stats) any {
		return fmt.Sprint(time.Duration(stats.TotalRuntime))
	})
	cols.MustSetExtractor("cumulruntime", func(stats *Stats) any {
		return fmt.Sprint(time.Duration(stats.CumulativeRuntime))
	})
	cols.MustSetExtractor("mapmemory", func(stats *Stats) any {
		return fmt.Sprint(units.BytesSize(float64(stats.MapMemory)))
	})

	return cols
}

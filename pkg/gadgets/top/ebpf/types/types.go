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
	"sort"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type SortBy int

const (
	ALL SortBy = iota
	RUNTIME
	RUNCOUNT
	PROGRAMID
	TOTALRUNTIME
	TOTALRUNCOUNT
)

const (
	MaxRowsDefault  = 20
	IntervalDefault = 1
	SortByDefault   = ALL
)

const (
	IntervalParam = "interval"
	MaxRowsParam  = "max_rows"
	SortByParam   = "sort_by"
)

var SortBySlice = []string{
	"all",
	"runtime",
	"runcount",
	"progid",
	"totalruntime",
	"totalruncount",
}

func (s SortBy) String() string {
	if int(s) < 0 || int(s) >= len(SortBySlice) {
		return "INVALID"
	}

	return SortBySlice[int(s)]
}

func ParseSortBy(sortby string) (SortBy, error) {
	for i, v := range SortBySlice {
		if v == sortby {
			return SortBy(i), nil
		}
	}
	return ALL, fmt.Errorf("%q is not a valid sort by value", sortby)
}

func SortStats(stats []Stats, sortBy SortBy) {
	sort.Slice(stats, func(i, j int) bool {
		a := stats[i]
		b := stats[j]

		switch sortBy {
		case RUNTIME:
			return a.CurrentRuntime > b.CurrentRuntime
		case RUNCOUNT:
			return a.CurrentRunCount > b.CurrentRunCount
		case TOTALRUNTIME:
			return a.TotalRuntime > b.TotalRuntime
		case TOTALRUNCOUNT:
			return a.TotalRunCount > b.TotalRunCount
		case PROGRAMID:
			return a.ProgramID > b.ProgramID
		default:
			return a.CurrentRuntime > b.CurrentRuntime && a.CurrentRunCount > b.CurrentRunCount
		}
	})
}

type Event struct {
	Error string `json:"error,omitempty"`

	// Node where the event comes from.
	Node string `json:"node,omitempty"`

	Stats []Stats `json:"stats,omitempty"`
}

type Stats struct {
	eventtypes.CommonData
	ProgramID       uint32     `json:"progid"`
	Pids            []*PidInfo `json:"pids,omitempty"`
	Name            string     `json:"name,omitempty"`
	Type            string     `json:"type,omitempty"`
	CurrentRuntime  int64      `json:"currentRuntime,omitempty"`
	CurrentRunCount uint64     `json:"currentRuncount,omitempty"`
	TotalRuntime    int64      `json:"totalRuntime,omitempty"`
	TotalRunCount   uint64     `json:"totalRuncount,omitempty"`
}

type PidInfo struct {
	Pid  uint32 `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

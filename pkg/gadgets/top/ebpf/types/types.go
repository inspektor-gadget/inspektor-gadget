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
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type SortBy int

const (
	ALL SortBy = iota
	RUNTIME
	RUNCOUNT
	PROGRAMID
	TOTALRUNTIME
	TOTALRUNCOUNT
	CUMULRUNTIME
	CUMULRUNCOUNT
	MAPMEMORY
	MAPCOUNT
)

const (
	MaxRowsDefault  = 20
	IntervalDefault = 1
)

var SortByDefault = []string{"-currentRuntime", "-currentRunCount"}

const (
	IntervalParam = "interval"
	MaxRowsParam  = "max_rows"
	SortByParam   = "sort_by"
)

type Event struct {
	Error string   `json:"error,omitempty"`
	Stats []*Stats `json:"stats,omitempty"`
}

type Stats struct {
	eventtypes.CommonData
	ProgramID          uint32     `json:"progid" column:"progid"`
	Pids               []*PidInfo `json:"pids,omitempty" column:"pids"`
	Name               string     `json:"name,omitempty" column:"name"`
	Type               string     `json:"type,omitempty" column:"type"`
	CurrentRuntime     int64      `json:"currentRuntime,omitempty" column:"currentRuntime"`
	CurrentRunCount    uint64     `json:"currentRunCount,omitempty" column:"currentRunCount"`
	CumulativeRuntime  int64      `json:"cumulRuntime,omitempty" column:"cumulRuntime"`
	CumulativeRunCount uint64     `json:"cumulRunCount,omitempty" column:"cumulRunCount"`
	TotalRuntime       int64      `json:"totalRuntime,omitempty" column:"totalRuntime"`
	TotalRunCount      uint64     `json:"totalRunCount,omitempty" column:"totalRunCount"`
	MapMemory          uint64     `json:"mapMemory,omitempty" column:"mapMemory"`
	MapCount           uint32     `json:"mapCount,omitempty" column:"mapCount"`
}

type PidInfo struct {
	Pid  uint32 `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

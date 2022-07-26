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
	"sort"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type SortBy int

const (
	ALL SortBy = iota
	READS
	WRITES
	RBYTES
	WBYTES
)

const (
	MaxRowsDefault  = 20
	IntervalDefault = 1
	SortByDefault   = ALL
	AllFilesDefault = false
)

const (
	IntervalParam = "interval"
	MaxRowsParam  = "max_rows"
	SortByParam   = "sort_by"
	AllFilesParam = "pid"
)

var SortBySlice = []string{
	"all",
	"reads",
	"writes",
	"rbytes",
	"wbytes",
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

// Event is the information the gadget sends to the client each capture
// interval
type Event struct {
	Error string `json:"error,omitempty"`

	// Node where the event comes from.
	Node string `json:"node,omitempty"`

	Stats []Stats `json:"stats,omitempty"`
}

// Stats represents the operations performed on a single file
type Stats struct {
	eventtypes.CommonData

	Reads      uint64 `json:"reads,omitempty"`
	Writes     uint64 `json:"writes,omitempty"`
	ReadBytes  uint64 `json:"rbytes,omitempty"`
	WriteBytes uint64 `json:"wbytes,omitempty"`
	Pid        uint32 `json:"pid,omitempty"`
	Tid        uint32 `json:"tid,omitempty"`
	MountNsID  uint64 `json:"mountnsid,omitempty"`
	Filename   string `json:"filename,omitempty"`
	Comm       string `json:"comm,omitempty"`
	FileType   byte   `json:"file_type,omitempty"`
}

func SortStats(stats []Stats, sortBy SortBy) {
	sort.Slice(stats, func(i, j int) bool {
		a := stats[i]
		b := stats[j]

		switch sortBy {
		case READS:
			return a.Reads > b.Reads
		case WRITES:
			return a.Writes > b.Writes
		case RBYTES:
			return a.ReadBytes > b.ReadBytes
		case WBYTES:
			return a.WriteBytes > b.WriteBytes
		default:
			return a.Reads > b.Reads && a.Writes > b.Writes &&
				a.ReadBytes > b.ReadBytes && a.WriteBytes > b.WriteBytes
		}
	})
}

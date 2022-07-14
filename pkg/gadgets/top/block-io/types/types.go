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
	"strings"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type SortBy int

const (
	ALL SortBy = iota
	IO
	BYTES
	TIME
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
	"io",
	"bytes",
	"time",
}

func (s SortBy) String() string {
	if int(s) < 0 || int(s) >= len(SortBySlice) {
		return "INVALID"
	}

	return SortBySlice[int(s)]
}

func ParseSortBy(sortBy string) (SortBy, error) {
	for i, v := range SortBySlice {
		if v == sortBy {
			return SortBy(i), nil
		}
	}
	return ALL, fmt.Errorf("%q is not a valid sort by value, possible values are: %q", sortBy, strings.Join(SortBySlice, ", "))
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

	Write      bool   `json:"write,omitempty"`
	Major      int    `json:"major,omitempty"`
	Minor      int    `json:"minor,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`
	MicroSecs  uint64 `json:"us,omitempty"`
	Operations uint32 `json:"io,omitempty"`
	MountNsID  uint64 `json:"mountnsid,omitempty"`
	Pid        int32  `json:"pid,omitempty"`
	Comm       string `json:"comm,omitempty"`
}

func SortStats(stats []Stats, sortBy SortBy) {
	sort.Slice(stats, func(i, j int) bool {
		a := stats[i]
		b := stats[j]

		switch sortBy {
		case IO:
			return a.Operations > b.Operations
		case BYTES:
			return a.Bytes > b.Bytes
		case TIME:
			return a.MicroSecs > b.MicroSecs
		default:
			return a.Operations > b.Operations && a.Bytes > b.Bytes && a.MicroSecs > b.MicroSecs
		}
	})
}

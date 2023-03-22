// Copyright 2022 The Inspektor Gadget authors
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

package top

import (
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	columnssort "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
)

const (
	MaxRowsDefault  = 20
	IntervalDefault = 1

	IntervalParam = "interval"
	MaxRowsParam  = "max_rows"
	SortByParam   = "sort_by"
)

type Event[T any] struct {
	Error string `json:"error,omitempty"`
	Stats []*T   `json:"stats,omitempty"`
}

func SortStats[T any](stats []*T, sortBy []string, colMap *columns.ColumnMap[T]) {
	columnssort.SortEntries(*colMap, stats, sortBy)
}

// ComputeIterations returns the number of iterations to perform to get the
// desired timeout. It returns zero if timeout is zero.
func ComputeIterations(interval, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		return 0, nil
	}
	if timeout < interval {
		return 0, fmt.Errorf("timeout must be greater than interval")
	}
	if timeout%interval != 0 {
		return 0, fmt.Errorf("timeout must be a multiple of interval")
	}
	return int(timeout / interval), nil
}

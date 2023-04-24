// Copyright 2023 The Inspektor Gadget authors
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

// Package histogram provides a Histogram struct that represents a histogram of
// the number of events that occurred in each interval. It also provides a way
// to transform a Histogram struct into a graphical representation. In addition,
// it allows to create a Histogram struct from an exp-2 histogram.
package histogram

import (
	"fmt"
	"strings"
)

type Unit string

const (
	UnitMilliseconds Unit = "ms"
	UnitMicroseconds Unit = "µs"
)

type Interval struct {
	Count uint64 `json:"count"`
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// Histogram represents a histogram of the number of events that occurred in
// each interval.
type Histogram struct {
	Unit      Unit       `json:"unit,omitempty"`
	Intervals []Interval `json:"intervals,omitempty"`
}

// NewIntervalsFromExp2Slots creates a new Interval array from an exp-2
// histogram represented in slots.
func NewIntervalsFromExp2Slots(slots []uint32) []Interval {
	if len(slots) == 0 {
		return nil
	}

	intervals := make([]Interval, 0, len(slots))
	indexMax := 0
	for i, val := range slots {
		if val > 0 {
			indexMax = i
		}

		start := uint64(1) << i
		end := 2*start - 1
		if start == 1 {
			start = 0
		}

		intervals = append(intervals, Interval{
			Count: uint64(val),
			Start: start,
			End:   end,
		})
	}

	// The element parsedIntervals[indexMax] is the last element with a non-zero
	// value. So, we need to use parsedIntervals[:indexMax+1] to include it in
	// the returned array.
	return intervals[:indexMax+1]
}

// String returns a string representation of the histogram. It is a golang
// adaption of iovisor/bcc print_log2_hist():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L895-L932
func (h *Histogram) String() string {
	if len(h.Intervals) == 0 {
		return ""
	}

	valMax := uint64(0)
	for _, b := range h.Intervals {
		if b.Count > valMax {
			valMax = b.Count
		}
	}

	spaceBefore := 8
	spaceAfter := 16
	width := 10
	stars := 40

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%*s%-*s : count    distribution\n", spaceBefore,
		"", spaceAfter, h.Unit))

	for _, b := range h.Intervals {
		sb.WriteString(fmt.Sprintf("%*d -> %-*d : %-8d |%s|\n", width,
			b.Start, width, b.End, b.Count,
			starsToString(b.Count, valMax, uint64(stars))))
	}

	return sb.String()
}

// starsToString returns a string with the number of stars and spaces needed to
// represent the value in the histogram. It is a golang adaption of iovisor/bcc
// print_stars():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L878-L893
func starsToString(val, valMax, width uint64) string {
	if valMax == 0 {
		return strings.Repeat(" ", int(width))
	}

	stars := val * width / valMax
	spaces := width - stars

	var sb strings.Builder
	sb.WriteString(strings.Repeat("*", int(stars)))
	sb.WriteString(strings.Repeat(" ", int(spaces)))

	return sb.String()
}

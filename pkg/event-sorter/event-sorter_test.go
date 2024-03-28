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

package eventsorter

import (
	"testing"
	"time"
)

func TestEventSorter(t *testing.T) {
	t.Parallel()

	type event struct {
		name       string
		timestamp  uint64
		appendTime string
	}

	timeFormat := time.RFC3339Nano
	tests := []struct {
		name             string
		events           []event
		eventsAppendTime []uint64
		processTime      string
		expectedOutput   string
		expectedNextTick string
	}{
		{
			name:             "no events",
			events:           []event{},
			processTime:      "2022-12-15T11:00:00.000000000Z",
			expectedOutput:   "",
			expectedNextTick: "0s",
		},
		{
			name: "events already sorted",
			events: []event{
				{
					name:       "A",
					timestamp:  1000,
					appendTime: "2022-12-15T11:00:00.000000000Z",
				},
				{
					name:       "B",
					timestamp:  2000,
					appendTime: "2022-12-15T11:00:01.000000000Z",
				},
				{
					name:       "C",
					timestamp:  3000,
					appendTime: "2022-12-15T11:00:02.000000000Z",
				},
			},
			processTime:      "2022-12-15T11:00:10.000000000Z",
			expectedOutput:   "ABC",
			expectedNextTick: "0s",
		},
		{
			name: "events already sorted but one too recent",
			events: []event{
				{
					name:       "A",
					timestamp:  1000,
					appendTime: "2022-12-15T11:00:00.000000000Z",
				},
				{
					name:       "B",
					timestamp:  2000,
					appendTime: "2022-12-15T11:00:01.000000000Z",
				},
				{
					name:       "C",
					timestamp:  3000,
					appendTime: "2022-12-15T11:00:02.000000000Z",
				},
				{
					name:       "D",
					timestamp:  4000,
					appendTime: "2022-12-15T11:00:09.500000000Z",
				},
			},
			processTime:      "2022-12-15T11:00:10.000000000Z",
			expectedOutput:   "ABC",
			expectedNextTick: "500ms",
		},
		{
			name: "events not sorted",
			events: []event{
				{
					name:       "C",
					timestamp:  3000,
					appendTime: "2022-12-15T11:00:01.000000000Z",
				},
				{
					name:       "B",
					timestamp:  2000,
					appendTime: "2022-12-15T11:00:02.000000000Z",
				},
				{
					name:       "A",
					timestamp:  1000,
					appendTime: "2022-12-15T11:00:03.000000000Z",
				},
			},
			processTime:      "2022-12-15T11:00:10.000000000Z",
			expectedOutput:   "ABC",
			expectedNextTick: "0s",
		},
		{
			name: "events not sorted but one too recent",
			events: []event{
				{
					name:       "C",
					timestamp:  3000,
					appendTime: "2022-12-15T11:00:01.000000000Z",
				},
				{
					name:       "B",
					timestamp:  2000,
					appendTime: "2022-12-15T11:00:02.000000000Z",
				},
				{
					name:       "A",
					timestamp:  1000,
					appendTime: "2022-12-15T11:00:03.000000000Z",
				},
				{
					name:       "D",
					timestamp:  4000,
					appendTime: "2022-12-15T11:00:09.500000000Z",
				},
			},
			processTime:      "2022-12-15T11:00:10.000000000Z",
			expectedOutput:   "ABC",
			expectedNextTick: "500ms",
		},
		{
			name: "events not sorted and several too recent",
			events: []event{
				{
					name:       "C",
					timestamp:  3000,
					appendTime: "2022-12-15T11:00:01.000000000Z",
				},
				{
					name:       "B",
					timestamp:  2000,
					appendTime: "2022-12-15T11:00:02.000000000Z",
				},
				{
					name:       "A",
					timestamp:  1000,
					appendTime: "2022-12-15T11:00:03.000000000Z",
				},
				{
					name:       "E",
					timestamp:  5000,
					appendTime: "2022-12-15T11:00:09.500000000Z",
				},
				{
					name:       "D",
					timestamp:  4000,
					appendTime: "2022-12-15T11:00:09.600000000Z",
				},
				{
					name:       "F",
					timestamp:  6000,
					appendTime: "2022-12-15T11:00:09.700000000Z",
				},
			},
			processTime:      "2022-12-15T11:00:10.000000000Z",
			expectedOutput:   "ABC",
			expectedNextTick: "500ms",
		},
	}

	for _, tt := range tests {
		t.Logf("Test %q\n", tt.name)
		es := NewEventSorter(WithCustomDelay(time.Second))
		output := ""
		for i, e := range tt.events {
			e := e
			appendTime, err := time.Parse(timeFormat, e.appendTime)
			if err != nil {
				t.Fatal(err)
			}
			callback := func() {
				output += e.name
			}
			resetTicker := es.appendAtTime(e.timestamp, appendTime, callback)
			if resetTicker != (i == 0) {
				t.Fatal("appendAtTime didn't rearm the ticker")
			}
		}
		processTime, err := time.Parse(timeFormat, tt.processTime)
		if err != nil {
			t.Fatal(err)
		}
		nextTick := es.process(processTime)
		if output != tt.expectedOutput {
			t.Fatalf("test %q failed: found %q, expected %q", tt.name, output, tt.expectedOutput)
		}
		expectedNextTick, err := time.ParseDuration(tt.expectedNextTick)
		if err != nil {
			t.Fatal(err)
		}
		if nextTick != expectedNextTick {
			t.Fatalf("test %q failed: next tick %q, expected %q", tt.name, nextTick.String(), tt.expectedNextTick)
		}

		es.Close()
	}
}

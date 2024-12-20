// Copyright 2024 The Inspektor Gadget authors
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

package main

import (
	"time"
	"unsafe"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	return 0
}

//export gadgetStart
func gadgetStart() int {
	type event struct {
		a      uint32
		b      uint32
		c      uint8
		unused [247]uint8
	}

	mapName := "events"
	perfArray, err := api.GetMap(mapName)
	if err != nil {
		api.Errorf("%s map exists", mapName)
		return 1
	}

	perfReader, err := api.NewPerfReader(perfArray, uint32(4096), true)
	if err != nil {
		api.Errorf("creating perf reader")
		return 1
	}
	defer perfReader.Close()

	_, err = perfReader.Read()
	if err == nil {
		api.Errorf("perf reader must be paused before reading")
		return 1
	}

	err = perfReader.Pause()
	if err != nil {
		api.Errorf("pausing perf reader")
		return 1
	}

	err = perfReader.SetDeadline(time.Now())
	if err != nil {
		api.Errorf("setting perf reader deadline to now")
		return 1
	}

	buf, err := perfReader.Read()
	if err != nil {
		api.Errorf("reading perf record")
	}

	if buf == nil {
		api.Errorf("buffer should not be nil")
		return 1
	}

	expectedEvent := event{a: 42, b: 42, c: 43}
	ev := *(*event)(unsafe.Pointer(&buf[0]))
	if ev != expectedEvent {
		api.Errorf("record read mismatch: expected %v, got %v", expectedEvent, ev)
		return 1
	}

	err = perfReader.Resume()
	if err != nil {
		api.Errorf("resuming perf reader")
		return 1
	}

	return 0
}

func main() {}

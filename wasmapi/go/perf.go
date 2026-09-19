// Copyright 2024-2025 The Inspektor Gadget authors
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

package api

import (
	"fmt"
	"os"
	_ "unsafe"
)

//go:wasmimport ig newPerfReader
//go:linkname newPerfReader newPerfReader
func newPerfReader(mapHandle uint32, size uint32, isOverwritable uint32) uint32

//go:wasmimport ig perfReaderPause
//go:linkname perfReaderPause perfReaderPause
func perfReaderPause(perfMapHandle uint32) uint32

//go:wasmimport ig perfReaderResume
//go:linkname perfReaderResume perfReaderResume
func perfReaderResume(perfMapHandle uint32) uint32

//go:wasmimport ig perfReaderRead
//go:linkname perfReaderRead perfReaderRead
func perfReaderRead(perfMapHandle uint32, dst uint64) uint32

//go:wasmimport ig perfReaderClose
//go:linkname perfReaderClose perfReaderClose
func perfReaderClose(perfMapHandle uint32) uint32

type PerfReader uint32

func NewPerfReader(m Map, size uint32, isOverwritable bool) (PerfReader, error) {
	var isOverwritableUint32 uint32
	if isOverwritable {
		isOverwritableUint32 = 1
	}

	ret := newPerfReader(uint32(m), size, isOverwritableUint32)
	if ret == 0 {
		return 0, fmt.Errorf("creating perf reader for map handle %d", m)
	}

	return PerfReader(ret), nil
}

func (p PerfReader) Pause() error {
	ret := perfReaderPause(uint32(p))
	if ret != 0 {
		return fmt.Errorf("pausing perf reader handle %d", p)
	}

	return nil
}

func (p PerfReader) Resume() error {
	ret := perfReaderResume(uint32(p))
	if ret != 0 {
		return fmt.Errorf("resuming perf reader handle %d", p)
	}

	return nil
}

func (p PerfReader) Read(dst []byte) error {
	ret := perfReaderRead(uint32(p), uint64(bytesToBufPtr(dst)))
	switch ret {
	case 0:
		return nil
	case 1:
		return fmt.Printf("reading perf reader record from perf reader handle %d", p)
	case 2:
		return os.ErrDeadlineExceeded
	default:
		return fmt.Errorf("bad return value from perfReaderRead: expected 0, 1 or 2, got %d", ret)
	}
}

func (p PerfReader) Close() error {
	ret := perfReaderClose(uint32(p))
	if ret != 0 {
		return fmt.Errorf("closing perf reader handle %d", p)
	}

	return nil
}

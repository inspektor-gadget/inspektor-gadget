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

package wasm

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func (i *wasmOperatorInstance) addPerfFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "newPerfReader", i.newPerfReader,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Perf map handle
			wapi.ValueTypeI32, // Size
			wapi.ValueTypeI32, // Overwritable
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // PerfReader
	)

	exportFunction(env, "perfReaderPause", i.perfReaderPause,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // PerfReader
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "perfReaderResume", i.perfReaderResume,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // PerfReader
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "perfReaderSetDeadline", i.perfReaderSetDeadline,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // PerfReader
			wapi.ValueTypeI64, // Nanoseconds
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "perfReaderRead", i.perfReaderRead,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // PerfReader
			wapi.ValueTypeI32, // Buf pointer address
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "perfReaderClose", i.perfReaderClose,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // PerfReader
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

// newPerfReader creates a new perf reader.
// Params:
// - stack[0] is the perf map handle
// - stack[1] is the size
// - stack[2] is a boolean indicating whether the perf buffer is overwritable
// - stack[3] is the value size
// - stack[4] is the max entries
// Return value:
// - Perf reader handle on success, 0 on error
func (i *wasmOperatorInstance) newPerfReader(ctx context.Context, m wapi.Module, stack []uint64) {
	perfMapHandle := wapi.DecodeU32(stack[0])
	size := int(wapi.DecodeU32(stack[1]))
	isOverwritable := wapi.DecodeU32(stack[2]) > 0

	perfMap, ok := getHandle[*ebpf.Map](i, perfMapHandle)
	if !ok {
		stack[0] = 1
		return
	}

	perfReader, err := perf.NewReaderWithOptions(perfMap, size, perf.ReaderOptions{Overwritable: isOverwritable})
	if err != nil {
		i.logger.Warnf("newPerfReader: creating perf reader: %v", err)
		stack[0] = 0
		return
	}

	stack[0] = wapi.EncodeU32(i.addHandle(perfReader))
}

// perfReaderPause() pauses the perf reader
// Params:
// - stack[0]: Perf reader handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) perfReaderPause(ctx context.Context, m wapi.Module, stack []uint64) {
	perfReaderHandle := wapi.DecodeU32(stack[0])

	perfReader, ok := getHandle[*perf.Reader](i, perfReaderHandle)
	if !ok {
		stack[0] = 1
		return
	}

	err := perfReader.Pause()
	if err != nil {
		i.logger.Warnf("perfReaderPause: pausing perf reader: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// perfReaderResume() resume the perf reader
// Params:
// - stack[0]: Perf reader handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) perfReaderResume(ctx context.Context, m wapi.Module, stack []uint64) {
	perfReaderHandle := wapi.DecodeU32(stack[0])

	perfReader, ok := getHandle[*perf.Reader](i, perfReaderHandle)
	if !ok {
		stack[0] = 1
		return
	}

	err := perfReader.Resume()
	if err != nil {
		i.logger.Warnf("perfReaderResume: resuming perf reader: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// perfReaderSetDeadline() set the perf reader deadline
// Params:
// - stack[0]: Perf reader handle
// - stack[1]: Time in nanoseconds
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) perfReaderSetDeadline(ctx context.Context, m wapi.Module, stack []uint64) {
	perfReaderHandle := wapi.DecodeU32(stack[0])
	nsec := stack[1]

	perfReader, ok := getHandle[*perf.Reader](i, perfReaderHandle)
	if !ok {
		stack[0] = 1
		return
	}

	perfReader.SetDeadline(time.Unix(0, int64(nsec)))

	stack[0] = 0
}

// perfReaderRead read one record from the perf reader.
// Params:
// - stack[0]: Perf reader handle
// - stack[1]: bufPtr address
// Return value:
// - 0 on success, 1 on error, 2 on deadline exceeded
func (i *wasmOperatorInstance) perfReaderRead(ctx context.Context, m wapi.Module, stack []uint64) {
	perfReaderHandle := wapi.DecodeU32(stack[0])
	addrBufPtr := wapi.DecodeU32(stack[1])

	perfReader, ok := getHandle[*perf.Reader](i, perfReaderHandle)
	if !ok {
		stack[0] = 1
		return
	}

	record, err := perfReader.Read()
	if err != nil {
		i.logger.Warnf("perfReaderRead: reading perf buffer: %v", err)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			stack[0] = 2
			return
		} else {
			stack[0] = 1
			return
		}
	}

	bufPtr, err := i.writeToGuestMemory(ctx, record.RawSample)
	if err != nil {
		i.logger.Warnf("perfReaderRead: writing record raw bytes to guest memory: %v", err)
		stack[0] = 1
		return
	}

	if !m.Memory().WriteUint64Le(addrBufPtr, bufPtr) {
		i.logger.Warnf("perfReaderRead: writing %x at %x", bufPtr, addrBufPtr)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// perfReaderClose() close the perf reader
// Params:
// - stack[0]: Perf reader handle
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) perfReaderClose(ctx context.Context, m wapi.Module, stack []uint64) {
	perfReaderHandle := wapi.DecodeU32(stack[0])

	perfReader, ok := getHandle[*perf.Reader](i, perfReaderHandle)
	if !ok {
		stack[0] = 1
		return
	}

	err := perfReader.Close()
	if err != nil {
		i.logger.Warnf("perfReaderClose: resuming perf reader: %v", err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

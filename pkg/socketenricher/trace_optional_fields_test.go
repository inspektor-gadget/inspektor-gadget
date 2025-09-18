//go:build linux
// +build linux

// Copyright 2025 The Inspektor Gadget authors
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

package socketenricher

import (
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type socketEnricherMapEntryBytes struct {
	Key   socketenricherGadgetSocketKey
	Value []byte
}

type fieldOffset struct {
	start uintptr
	end   uintptr
}

type offsets struct {
	cwd     fieldOffset
	exepath fieldOffset
}

func firstN(str string, n int) string {
	if n >= len(str) {
		return str
	}
	return str[:n]
}

func TestSocketEnricherOptionalFields(t *testing.T) {
	t.Parallel()

	utils.RequireRoot(t)
	utils.HostInit(t)

	cwd, err := os.Getwd()
	require.NoError(t, err, "Cannot get current working directory")
	exepath, err := os.Readlink("/proc/self/exe")
	require.NoError(t, err, "Cannot get current executable path")

	optionalFieldsStart := unsafe.Offsetof(socketenricherGadgetSocketValue{}.OptionalFieldsStart)

	type expectedEvent struct {
		cwd     string
		exepath string
	}

	type testCase struct {
		seConfig      Config
		offsets       offsets
		expectedEvent *expectedEvent
	}

	tests := map[string]testCase{
		"all_disabled": {
			seConfig: Config{},
			offsets:  offsets{},
		},
		"cwd_512_exepath_0": {
			seConfig: Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    512,
				},
			},
			offsets: offsets{
				cwd: fieldOffset{
					start: optionalFieldsStart,
					end:   optionalFieldsStart + 512,
				},
			},
			expectedEvent: &expectedEvent{
				cwd:     firstN(cwd, 511),
				exepath: "",
			},
		},
		"cwd_0_exepath_512": {
			seConfig: Config{
				Exepath: FieldConfig{
					Enabled: true,
					Size:    512,
				},
			},
			offsets: offsets{
				exepath: fieldOffset{
					start: optionalFieldsStart,
					end:   optionalFieldsStart + 512,
				},
			},
			expectedEvent: &expectedEvent{
				cwd:     "",
				exepath: firstN(exepath, 511),
			},
		},
		"cwd_512_exepath_512": {
			seConfig: Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    512,
				},
				Exepath: FieldConfig{
					Enabled: true,
					Size:    512,
				},
			},
			offsets: offsets{
				cwd: fieldOffset{
					start: optionalFieldsStart,
					end:   optionalFieldsStart + 512,
				},
				exepath: fieldOffset{
					start: optionalFieldsStart + 512,
					end:   optionalFieldsStart + 512 + 512,
				},
			},
			expectedEvent: &expectedEvent{
				cwd:     firstN(cwd, 511),
				exepath: firstN(exepath, 511),
			},
		},
		"cwd_32_exepath_4": {
			seConfig: Config{
				Cwd: FieldConfig{
					Enabled: true,
					Size:    32,
				},
				Exepath: FieldConfig{
					Enabled: true,
					Size:    4,
				},
			},
			offsets: offsets{
				cwd: fieldOffset{
					start: optionalFieldsStart,
					end:   optionalFieldsStart + 32,
				},
				exepath: fieldOffset{
					start: optionalFieldsStart + 32,
					end:   optionalFieldsStart + 32 + 4,
				},
			},
			expectedEvent: &expectedEvent{
				cwd:     firstN(cwd, 31),
				exepath: firstN(exepath, 3),
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runner := utils.NewRunnerWithTest(t, nil)

			// We will test 2 scenarios with 2 different tracers:
			// 1. earlyTracer will be started before the event is generated
			// 2. lateTracer will be started after the event is generated
			earlyTracer, err := NewSocketEnricher(tc.seConfig)
			require.NoError(t, err)
			t.Cleanup(earlyTracer.Close)

			// Generate the event in the fake container
			var port uint16
			var fd int
			utils.RunWithRunner(t, runner, func() error {
				var err error
				port, fd, err = bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_DGRAM, 0)()
				t.Cleanup(func() {
					// cleanup only if it has not been already closed
					if fd != -1 {
						unix.Close(fd)
					}
				})
				return err
			})

			checkEntries := func(entries []socketEnricherMapEntryBytes) {
				if tc.expectedEvent == nil {
					return
				}

				for _, entry := range entries {
					if entry.Key.Port != port {
						continue
					}

					cwdBytes := ""
					if tc.expectedEvent.cwd != "" {
						cwdBytes = gadgets.FromCString(entry.Value[tc.offsets.cwd.start:tc.offsets.cwd.end])
					}

					exepathBytes := ""
					if tc.expectedEvent.exepath != "" {
						exepathBytes = gadgets.FromCString(entry.Value[tc.offsets.exepath.start:tc.offsets.exepath.end])
					}

					if cwdBytes == tc.expectedEvent.cwd && exepathBytes == tc.expectedEvent.exepath {
						return
					}
				}
				t.Fatal("entry not found")
			}

			// Start the late tracer after the event has been generated
			lateTracer, err := NewSocketEnricher(tc.seConfig)
			require.NoError(t, err)
			t.Cleanup(lateTracer.Close)

			t.Logf("Testing if early tracer noticed the event")
			entries := socketsMapEntriesBytes(t, earlyTracer)
			checkEntries(entries)

			t.Logf("Testing if late tracer noticed the event")
			entries2 := socketsMapEntriesBytes(t, lateTracer)
			checkEntries(entries2)
		})
	}
}

func socketsMapEntriesBytes(
	t *testing.T,
	tracer *SocketEnricher,
) (entries []socketEnricherMapEntryBytes) {
	iter := tracer.SocketsMap().Iterate()
	var key socketenricherGadgetSocketKey
	value := make([]byte, unsafe.Sizeof(socketenricherGadgetSocketValue{}))
	for iter.Next(&key, &value) {
		entry := socketEnricherMapEntryBytes{
			Key:   key,
			Value: value,
		}
		entries = append(entries, entry)
		value = make([]byte, unsafe.Sizeof(socketenricherGadgetSocketValue{}))
	}
	require.NoError(t, iter.Err(), "Cannot iterate over socket enricher map")
	return entries
}

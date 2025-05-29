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

package processhelpers_test

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
)

type allOptions struct {
	totalMemory uint64
	cpuCount    int
}

func (a allOptions) WithCPUUsage() bool {
	return true
}

func (a allOptions) WithCPUUsageRelative() bool {
	return true
}

func (a allOptions) WithComm() bool {
	return true
}

func (a allOptions) WithPPID() bool {
	return true
}

func (a allOptions) WithState() bool {
	return true
}

func (a allOptions) WithUID() bool {
	return true
}

func (a allOptions) WithVmSize() bool {
	return true
}

func (a allOptions) WithVmRSS() bool {
	return true
}

func (a allOptions) WithMemoryRelative() bool {
	return true
}

func (a allOptions) WithThreadCount() bool {
	return true
}

func (a allOptions) WithStartTime() bool {
	return true
}

func (a allOptions) TotalMemory() uint64 {
	return a.totalMemory
}

func (a allOptions) NumCPU() int {
	return a.cpuCount
}

func (a allOptions) LastCPUTime(pid int) (uint64, bool) {
	return 0, false
}

func (a allOptions) BootTime() time.Time {
	return time.Now()
}

func TestGetProcessInfo(t *testing.T) {
	pid := os.Getpid()
	proc, err := processhelpers.GetProcessInfo(pid, 0, allOptions{
		cpuCount: 1,
	})
	require.NoError(t, err)

	assert.Equal(t, pid, proc.PID)
	assert.Greater(t, proc.PPID, 0)
	assert.NotEmpty(t, proc.Comm)
	assert.Zero(t, proc.CPUUsage)
	assert.Zero(t, proc.CPUUsageRelative)
	assert.NotZero(t, proc.MemoryRSS)
	assert.NotZero(t, proc.MemoryVirtual)
	assert.NotZero(t, proc.ThreadCount)
	assert.Equal(t, proc.State, "R")
	assert.NotZero(t, proc.StartTime)
}

func BenchmarkSingle(b *testing.B) {
	pid := os.Getpid()
	opts := allOptions{cpuCount: 1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processhelpers.GetProcessInfo(pid, 0, opts)
	}
}

func BenchmarkAllProcessesSeq(b *testing.B) {
	entries, err := os.ReadDir("/proc")
	require.NoError(b, err)
	opts := allOptions{cpuCount: 1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, entry := range entries {
			// Skip non-directories and non-numeric names (not PIDs)
			if !entry.IsDir() {
				continue
			}

			pid64, err := strconv.ParseInt(entry.Name(), 10, 32)
			if err != nil {
				// Not a process directory
				continue
			}
			pid := int(pid64)
			processhelpers.GetProcessInfo(pid, 0, opts)
		}
	}
}

func BenchmarkAllProcessesParallel(b *testing.B) {
	entries, err := os.ReadDir("/proc")
	require.NoError(b, err)
	opts := allOptions{cpuCount: 1}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		q := make(chan int, 64)
		for i := 0; i < runtime.NumCPU(); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for pid := range q {
					processhelpers.GetProcessInfo(pid, 0, opts)
				}
			}()
		}
		for _, entry := range entries {
			// Skip non-directories and non-numeric names (not PIDs)
			if !entry.IsDir() {
				continue
			}

			pid64, err := strconv.ParseInt(entry.Name(), 10, 32)
			if err != nil {
				// Not a process directory
				continue
			}
			pid := int(pid64)
			q <- pid
		}
		close(q)
		wg.Wait()
	}
}

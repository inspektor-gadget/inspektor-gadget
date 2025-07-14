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

package stats

import (
	"fmt"
	"runtime"
	"time"

	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
)

type processCpu struct {
	lastCpuTimes map[int]uint64
	comms        []string
}

// Implementation of Options interface
func (m *processCpu) WithCPUUsage() bool         { return true }
func (m *processCpu) WithCPUUsageRelative() bool { return true }
func (m *processCpu) WithComm() bool             { return false }
func (m *processCpu) WithPPID() bool             { return false }
func (m *processCpu) WithState() bool            { return false }
func (m *processCpu) WithUID() bool              { return false }
func (m *processCpu) WithVmSize() bool           { return false }
func (m *processCpu) WithVmRSS() bool            { return false }
func (m *processCpu) WithMemoryRelative() bool   { return false }
func (m *processCpu) WithThreadCount() bool      { return false }
func (m *processCpu) WithStartTime() bool        { return false }

func (m *processCpu) TotalMemory() uint64 {
	return 0
}

func (m *processCpu) NumCPU() int {
	return runtime.NumCPU()
}

func (m *processCpu) LastCPUTime(pid int) (uint64, bool) {
	t, ok := m.lastCpuTimes[pid]
	return t, ok
}

func (m *processCpu) BootTime() time.Time {
	return time.Now()
}

func (m *processCpu) getProcessCpu(timeDelta float64) (map[string]float64, error) {
	ret := make(map[string]float64)
	lastCpuTimes := make(map[int]uint64)

	// TODO: should we "continue" in case of error?
	for _, comm := range m.comms {
		pid, err := findProcessByComm(comm)
		if err != nil {
			return nil, err
		}

		processInfo, err := processhelpers.GetProcessInfo(pid, timeDelta, m)
		if err != nil {
			return nil, fmt.Errorf("getting process info for pid %d: %w", pid, err)
		}

		lastCpuTimes[pid] = processInfo.CPUTime

		ret[comm] = processInfo.CPUUsageRelative
	}

	m.lastCpuTimes = lastCpuTimes

	return ret, nil
}

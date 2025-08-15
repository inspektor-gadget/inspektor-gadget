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

type processMemory struct {
	totalMemory uint64
	comms       []string
}

// Implementation of Options interface
func (m *processMemory) WithCPUUsage() bool         { return false }
func (m *processMemory) WithCPUUsageRelative() bool { return false }
func (m *processMemory) WithComm() bool             { return false }
func (m *processMemory) WithPPID() bool             { return false }
func (m *processMemory) WithState() bool            { return false }
func (m *processMemory) WithUID() bool              { return false }
func (m *processMemory) WithVmSize() bool           { return false }
func (m *processMemory) WithVmRSS() bool            { return true }
func (m *processMemory) WithMemoryRelative() bool   { return true }
func (m *processMemory) WithThreadCount() bool      { return false }
func (m *processMemory) WithStartTime() bool        { return false }

func (m *processMemory) TotalMemory() uint64 {
	return m.totalMemory
}

func (m *processMemory) NumCPU() int {
	return runtime.NumCPU()
}

func (m *processMemory) LastCPUTime(pid int) (uint64, bool) {
	return 0, false
}

func (m *processMemory) BootTime() time.Time {
	return time.Now()
}

func (m *processMemory) getProcessMemory() (map[string]uint64, error) {
	ret := make(map[string]uint64)

	// TODO: should we "continue" in case of error?
	for _, comm := range m.comms {
		pid, err := findProcessByComm(comm)
		if err != nil {
			return nil, err
		}

		processInfo, err := processhelpers.GetProcessInfo(pid, 0, m)
		if err != nil {
			return nil, fmt.Errorf("getting process info for pid %d: %w", pid, err)
		}

		ret[comm] = processInfo.MemoryRSS
	}

	return ret, nil
}

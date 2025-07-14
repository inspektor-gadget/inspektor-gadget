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
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
)

// Implementation of Options interface
func (m *statsRecorder) WithCPUUsage() bool         { return true }
func (m *statsRecorder) WithCPUUsageRelative() bool { return true }
func (m *statsRecorder) WithComm() bool             { return false }
func (m *statsRecorder) WithPPID() bool             { return false }
func (m *statsRecorder) WithState() bool            { return false }
func (m *statsRecorder) WithUID() bool              { return false }
func (m *statsRecorder) WithVmSize() bool           { return false }
func (m *statsRecorder) WithVmRSS() bool            { return true }
func (m *statsRecorder) WithMemoryRelative() bool   { return true }
func (m *statsRecorder) WithThreadCount() bool      { return false }
func (m *statsRecorder) WithStartTime() bool        { return false }

func (m *statsRecorder) TotalMemory() uint64 {
	return m.totalMemory
}

func (m *statsRecorder) NumCPU() int {
	return runtime.NumCPU()
}

func (m *statsRecorder) LastCPUTime(pid int) (uint64, bool) {
	t, ok := m.lastCpuTimes[pid]
	return t, ok
}

func (m *statsRecorder) BootTime() time.Time {
	return time.Now()
}

func (m *statsRecorder) getProcessStats(timeDelta float64) (map[string]*Stat, error) {
	ret := make(map[string]*Stat)
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

		ret[comm] = &Stat{
			CPUPercentage: processInfo.CPUUsageRelative,
			Memory:        processInfo.MemoryRSS,
		}
	}

	m.lastCpuTimes = lastCpuTimes

	return ret, nil
}

func findProcessByComm(targetComm string) (int, error) {
	// Read /proc directory to find processes
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read the command name from /proc/PID/comm
		commPath := "/proc/" + entry.Name() + "/comm"
		commBytes, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(string(commBytes))
		if comm == targetComm {
			return pid, nil
		}
	}

	return 0, os.ErrNotExist
}

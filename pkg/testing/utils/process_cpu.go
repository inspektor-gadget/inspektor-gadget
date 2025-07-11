package utils

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
)

type processCpu struct {
	usage        []*CPUUsage
	done         chan struct{}
	initialDelay time.Duration
	comm         string
	lastCpuTime  uint64
}

func ProcessCpu(comm string, initialDelay time.Duration) *processCpu {
	return &processCpu{
		done:         make(chan struct{}),
		initialDelay: initialDelay,
		comm:         comm,
		//lastCPUTimes: make(map[int]uint64),
	}
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
	return m.lastCpuTime, true
}

func (m *processCpu) BootTime() time.Time {
	return time.Now()
}

func (m *processCpu) Run(t *testing.T) {
	t.Fatalf("Run not implemented for memory cmd, use Start() instead")
}

func (m *processCpu) Start(t *testing.T) {
	go func() {
		if m.initialDelay > 0 {
			time.Sleep(m.initialDelay)
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		last := time.Now()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				delta := now.Sub(last).Seconds()
				last = now

				// Find process by command name
				pid, err := m.findProcessByComm()
				if err != nil {
					//t.Logf("failed to find process with comm %s: %v", m.comm, err)
					continue
				}

				// Get process cpu information
				processInfo, err := processhelpers.GetProcessInfo(pid, delta, m)
				if err != nil {
					t.Errorf("failed to get process info for pid %d: %v", pid, err)
					continue
				}
				m.lastCpuTime = processInfo.CPUTime

				usage := &CPUUsage{
					Percentage: processInfo.CPUUsageRelative,
					Timestamp:  now,
				}

				m.usage = append(m.usage, usage)
			case <-m.done:
				return
			}
		}
	}()
}

// findProcessByComm finds a process PID by its command name
func (m *processCpu) findProcessByComm() (int, error) {
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
		if comm == m.comm {
			return pid, nil
		}
	}

	return 0, os.ErrNotExist
}

func (m *processCpu) Stop(t *testing.T) {
	close(m.done)
}

func (m *processCpu) IsStartAndStop() bool {
	return true
}

func (m *processCpu) Running() bool {
	return false
}

// Avg returns the average memory used in MB
func (m *processCpu) Avg() float64 {
	if len(m.usage) == 0 {
		return 0.0
	}

	totalSum := 0.0
	for _, usage := range m.usage {
		totalSum += usage.Percentage
	}
	return totalSum / float64(len(m.usage))
}

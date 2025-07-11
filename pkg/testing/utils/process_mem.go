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

type processMemory struct {
	usage        []*MemoryUsage
	done         chan struct{}
	initialDelay time.Duration
	comm         string
	totalMemory  uint64
	//lastCPUTimes map[int]uint64
}

func ProcessMemory(comm string, initialDelay time.Duration) *processMemory {
	totalMem, _ := processhelpers.GetTotalMemory()
	return &processMemory{
		done:         make(chan struct{}),
		initialDelay: initialDelay,
		comm:         comm,
		totalMemory:  totalMem,
		//lastCPUTimes: make(map[int]uint64),
	}
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

func (m *processMemory) Run(t *testing.T) {
	t.Fatalf("Run not implemented for memory cmd, use Start() instead")
}

func (m *processMemory) Start(t *testing.T) {
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

				// Get process memory information
				processInfo, err := processhelpers.GetProcessInfo(pid, delta, m)
				if err != nil {
					t.Errorf("failed to get process info for pid %d: %v", pid, err)
					continue
				}

				// Convert to MemoryUsage format
				usage := &MemoryUsage{
					UsedMB:     float64(processInfo.MemoryRSS) / (1024 * 1024), // Convert bytes to MB
					Percentage: processInfo.MemoryRelative,
					TotalMB:    float64(m.totalMemory) / (1024 * 1024), // Convert bytes to MB
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
func (m *processMemory) findProcessByComm() (int, error) {
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

func (m *processMemory) Stop(t *testing.T) {
	close(m.done)
}

func (m *processMemory) IsStartAndStop() bool {
	return true
}

func (m *processMemory) Running() bool {
	return false
}

// Avg returns the average memory used in MB
func (m *processMemory) Avg() float64 {
	if len(m.usage) == 0 {
		return 0.0
	}

	totalSum := 0.0
	for _, usage := range m.usage {
		totalSum += usage.UsedMB
	}
	return totalSum / float64(len(m.usage))
}

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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
)

// Option is a function that modifies the statsRecorder configuration
type Option func(*statsRecorder)

// WithComms sets the list of process command names to track
func WithComms(comms []string) Option {
	return func(s *statsRecorder) {
		s.comms = comms
	}
}

// WithInitialDelay sets the initial delay before starting stats collection
func WithInitialDelay(delay time.Duration) Option {
	return func(s *statsRecorder) {
		s.initialDelay = delay
	}
}

type Stat struct {
	// CPU usage in percentage.
	// 100% means all cores are fully utilized.
	CPUPercentage float64 `json:"cpu_percentage"`

	// Memory usage in bytes.
	Memory uint64 `json:"mem"`
}

type Stats struct {
	// System-wide statistics.
	System Stat `json:"system"`

	// Per-process statistics.
	Processes map[string]*Stat `json:"processes"`
}

type memStat struct {
	system    uint64
	processes map[string]uint64
}

type statsRecorder struct {
	memPoints []memStat

	prevCPUStats *CPUStats
	systemCpu    float64
	processesCpu map[string]float64
	iterations   int

	processMemory *processMemory
	processCpu    *processCpu

	running bool

	// opts
	// Comms of processes to track.
	comms []string

	// Initial delay before starting the stats collection.
	initialDelay time.Duration
}

func New(iterations int, opts ...Option) *statsRecorder {
	totalMem, _ := processhelpers.GetTotalMemory()

	sr := &statsRecorder{
		running:    false,
		iterations: iterations,
	}

	for _, opt := range opts {
		opt(sr)
	}

	if len(sr.comms) != 0 {
		sr.processMemory = &processMemory{
			totalMemory: totalMem,
			comms:       sr.comms,
		}

		sr.processCpu = &processCpu{
			lastCpuTimes: make(map[int]uint64),
			comms:        sr.comms,
		}
	}

	return sr
}

func (m *statsRecorder) Run(t *testing.T) {
	t.Fatalf("Run not implemented for statsRecorder cmd, use Start() instead")
}

func (m *statsRecorder) Start(t *testing.T) {
	go func() {
		if m.initialDelay > 0 {
			time.Sleep(m.initialDelay)
		}

		var err error
		m.prevCPUStats, err = readCPUStats()
		if err != nil {
			t.Errorf("failed to read initial CPU stats: %v", err)
			return
		}

		last := time.Now()
		if m.processCpu != nil {
			m.processesCpu, err = m.processCpu.getProcessCpu(0.0)
			if err != nil {
				t.Errorf("failed to read initial process CPU: %v", err)
				return
			}
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for i := 0; i < m.iterations; i++ {
			<-ticker.C
			point, err := m.getMemPoint()
			if err != nil {
				t.Logf("failed to get stats: %v", err)
				continue
			}
			m.memPoints = append(m.memPoints, point)
		}

		m.systemCpu, err = m.getSystemCPU()
		if err != nil {
			t.Errorf("failed to read system CPU: %v", err)
			return
		}

		now := time.Now()
		delta := now.Sub(last).Seconds()
		if m.processCpu != nil {
			m.processesCpu, err = m.processCpu.getProcessCpu(delta)
			if err != nil {
				t.Errorf("failed to read process CPU: %v", err)
				return
			}
		}

		m.running = false
	}()
}

func (m *statsRecorder) Stop(t *testing.T) {
	if m.running {
		t.Fatal("recorder is still running, cannot stop it")
	}
}

func (m *statsRecorder) IsStartAndStop() bool {
	return true
}

func (m *statsRecorder) Running() bool {
	return m.running
}

func (m *statsRecorder) Stats() Stats {
	if len(m.memPoints) == 0 {
		return Stats{}
	}

	processes := make(map[string]*Stat)
	for _, comm := range m.comms {
		processes[comm] = &Stat{}
	}

	// average memory usage across all points
	memAvg := uint64(0)
	for _, point := range m.memPoints {
		memAvg += point.system

		for comm, mem := range point.processes {
			processes[comm].Memory += mem
		}
	}
	memAvg /= uint64(len(m.memPoints))

	for _, stat := range processes {
		stat.Memory /= uint64(len(m.memPoints))
	}

	for comm, cpu := range m.processesCpu {
		if _, ok := processes[comm]; !ok {
			processes[comm] = &Stat{}
		}
		processes[comm].CPUPercentage = cpu
	}

	return Stats{
		System: Stat{
			CPUPercentage: m.systemCpu,
			Memory:        memAvg,
		},
		Processes: processes,
	}
}

func (m *statsRecorder) getMemPoint() (memStat, error) {
	systemMemory, err := m.getSystemMemory()
	if err != nil {
		return memStat{}, err
	}

	if m.processMemory == nil {
		return memStat{system: systemMemory}, nil
	}

	processes, err := m.processMemory.getProcessMemory()
	if err != nil {
		return memStat{}, err
	}

	return memStat{
		system:    systemMemory,
		processes: processes,
	}, nil
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

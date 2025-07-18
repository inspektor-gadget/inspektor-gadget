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

type statsRecorder struct {
	points       []Stats
	prevCPUStats *CPUStats

	//done       chan struct{}
	iterations int
	running    bool

	totalMemory  uint64
	lastCpuTimes map[int]uint64

	// opts
	// Comms of processes to track.
	comms []string

	// Initial delay before starting the stats collection.
	initialDelay time.Duration
}

func New(iterations int, opts ...Option) *statsRecorder {
	totalMem, _ := processhelpers.GetTotalMemory()

	sr := &statsRecorder{
		running:     false,
		totalMemory: totalMem,
		iterations:  iterations,
	}

	for _, opt := range opts {
		opt(sr)
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

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		last := time.Now()

		for i := 0; i < m.iterations; i++ {
			<-ticker.C
			now := time.Now()
			delta := now.Sub(last).Seconds()
			last = now

			point, err := m.getStats(delta)
			if err != nil {
				t.Logf("failed to get stats: %v", err)
				continue
			}
			m.points = append(m.points, point)
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
	if len(m.points) == 0 {
		return Stats{}
	}

	processes := make(map[string]*Stat)
	for _, comm := range m.comms {
		processes[comm] = &Stat{}
	}

	cpuAvg := 0.0
	memAvg := uint64(0)
	for _, point := range m.points {
		cpuAvg += point.System.CPUPercentage
		memAvg += point.System.Memory

		for comm, stat := range point.Processes {
			processes[comm].CPUPercentage += stat.CPUPercentage
			processes[comm].Memory += stat.Memory
		}
	}
	memAvg /= uint64(len(m.points))
	cpuAvg /= float64(len(m.points))

	for _, stat := range processes {
		stat.CPUPercentage /= float64(len(m.points))
		stat.Memory /= uint64(len(m.points))
	}

	return Stats{
		System: Stat{
			CPUPercentage: cpuAvg,
			Memory:        memAvg,
		},
		Processes: processes,
	}
}

func (m *statsRecorder) getStats(timeDelta float64) (Stats, error) {
	systemMemory, err := m.getSystemMemory()
	if err != nil {
		return Stats{}, err
	}

	systemCPU, err := m.getSystemCPU()
	if err != nil {
		return Stats{}, err
	}

	processes, err := m.getProcessStats(timeDelta)
	if err != nil {
		return Stats{}, err
	}

	return Stats{
		System: Stat{
			Memory:        systemMemory,
			CPUPercentage: systemCPU,
		},
		Processes: processes,
	}, nil
}

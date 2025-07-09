package utils

import (
	"fmt"
	"testing"
	"time"

	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
)

type memory struct {
	usage        []*MemoryUsage
	done         chan struct{}
	initialDelay time.Duration
}

func Memory(initialDelay time.Duration) *memory {
	return &memory{
		done:         make(chan struct{}),
		initialDelay: initialDelay,
	}
}

func (m *memory) Run(t *testing.T) {
	t.Fatalf("Run not implemented for memory cmd, use Start() instead")
}

func (m *memory) Start(t *testing.T) {
	go func() {
		if m.initialDelay > 0 {
			time.Sleep(m.initialDelay)
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				usage, err := m.getMemoryUsage()
				if err != nil {
					t.Errorf("failed to get memory usage: %v", err)
					continue
				}
				m.usage = append(m.usage, usage)
			case <-m.done:
				return
			}
		}
	}()
}

func (m *memory) Stop(t *testing.T) {
	close(m.done)
}

func (m *memory) IsStartAndStop() bool {
	return true
}

func (m *memory) Running() bool {
	return false
}

// Avg returns the average memory used in MB
func (m *memory) Avg() float64 {
	if len(m.usage) == 0 {
		return 0.0
	}

	totalSum := 0.0
	for _, usage := range m.usage {
		totalSum += usage.UsedMB
	}
	return totalSum / float64(len(m.usage))
}

// MemoryUsage represents memory usage percentage and absolute values
type MemoryUsage struct {
	// TODO
	Percentage float64
	UsedMB     float64
	// TODO
	TotalMB   float64
	Timestamp time.Time
}

func (m *memory) getMemoryUsage() (*MemoryUsage, error) {
	total, err := processhelpers.GetTotalMemory()
	if err != nil {
		return nil, fmt.Errorf("get total memory: %w", err)
	}
	return &MemoryUsage{
		UsedMB:    float64(total) / 1024.0,
		Timestamp: time.Now(),
	}, nil
}

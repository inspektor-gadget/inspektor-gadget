package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

// MemoryStats represents memory statistics at a point in time
type MemoryStats struct {
	MemTotal     uint64 // Total usable RAM (in kB)
	MemFree      uint64 // Amount of free RAM (in kB)
	MemAvailable uint64 // Available memory for new processes (in kB)
	Buffers      uint64 // Temporary storage for raw disk blocks (in kB)
	Cached       uint64 // In-memory cache for files read from disk (in kB)
	SReclaimable uint64 // Reclaimable slab memory (in kB)
}

// MemoryUsage represents memory usage percentage and absolute values
type MemoryUsage struct {
	Percentage float64
	UsedMB     float64
	TotalMB    float64
	Timestamp  time.Time
}

// readMemoryStats reads memory statistics from /proc/meminfo
func readMemoryStats() (*MemoryStats, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats := &MemoryStats{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "MemTotal":
			stats.MemTotal = value
		case "MemFree":
			stats.MemFree = value
		case "MemAvailable":
			stats.MemAvailable = value
		case "Buffers":
			stats.Buffers = value
		case "Cached":
			stats.Cached = value
		case "SReclaimable":
			stats.SReclaimable = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if stats.MemTotal == 0 {
		return nil, fmt.Errorf("failed to read MemTotal from /proc/meminfo")
	}

	return stats, nil
}

// calculateMemoryUsage calculates memory usage percentage and absolute values
func calculateMemoryUsage(stats *MemoryStats) *MemoryUsage {
	totalMB := float64(stats.MemTotal) / 1024.0

	// Calculate used memory more accurately
	// Available memory is a better indicator than just Free memory
	// as it accounts for reclaimable memory (buffers, cached, etc.)
	availableKB := stats.MemAvailable
	if availableKB == 0 {
		// Fallback calculation if MemAvailable is not available
		availableKB = stats.MemFree + stats.Buffers + stats.Cached + stats.SReclaimable
	}

	usedKB := stats.MemTotal - availableKB
	usedMB := float64(usedKB) / 1024.0

	percentage := (float64(usedKB) / float64(stats.MemTotal)) * 100.0

	return &MemoryUsage{
		Percentage: percentage,
		UsedMB:     usedMB,
		TotalMB:    totalMB,
		Timestamp:  time.Now(),
	}
}

func (m *memory) getMemoryUsage() (*MemoryUsage, error) {
	stats, err := readMemoryStats()
	if err != nil {
		return nil, fmt.Errorf("failed to read memory stats: %w", err)
	}

	usage := calculateMemoryUsage(stats)

	return usage, nil
}

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

type cpu struct {
	usage        []*CPUUsage
	prevStats    *CPUStats
	done         chan struct{}
	initialDelay time.Duration
}

func Cpu(initialDelay time.Duration) *cpu {
	return &cpu{
		done:         make(chan struct{}),
		initialDelay: initialDelay,
	}
}

func (c *cpu) Run(t *testing.T) {
	t.Fatalf("Run not implemented for cpu cmd, use Start() instead")
}

func (c *cpu) Start(t *testing.T) {
	go func() {
		if c.initialDelay > 0 {
			time.Sleep(c.initialDelay)
		}

		// Get initial CPU stats
		var err error
		c.prevStats, err = readCPUStats()
		if err != nil {
			t.Errorf("failed to read initial CPU stats: %v", err)
			return
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				usage, err := c.getCpuUsage()
				if err != nil {
					t.Errorf("failed to get CPU usage: %v", err)
					continue
				}
				c.usage = append(c.usage, usage)
			case <-c.done:
				return
			}
		}
	}()
}

func (c *cpu) Stop(t *testing.T) {
	close(c.done)
}

func (c *cpu) IsStartAndStop() bool {
	return true
}

func (c *cpu) Running() bool {
	return false
}

func (c *cpu) Avg() float64 {
	if len(c.usage) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, usage := range c.usage {
		sum += usage.Percentage
	}
	return sum / float64(len(c.usage))
}

// CPUStats represents CPU statistics at a point in time
type CPUStats struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
}

// CPUUsage represents CPU usage percentage and timestamp
type CPUUsage struct {
	Percentage float64
	Timestamp  time.Time
}

// readCPUStats reads CPU statistics from /proc/stat
func readCPUStats() (*CPUStats, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read first line from /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return nil, fmt.Errorf("invalid /proc/stat format")
	}

	stats := &CPUStats{}
	values := []*uint64{
		&stats.User,
		&stats.Nice,
		&stats.System,
		&stats.Idle,
		&stats.IOWait,
		&stats.IRQ,
		&stats.SoftIRQ,
		&stats.Steal,
	}

	for i, field := range fields[1:9] {
		val, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CPU stat field %d: %w", i, err)
		}
		*values[i] = val
	}

	return stats, nil
}

// calculateCPUUsage calculates CPU usage percentage between two stat readings
func calculateCPUUsage(prev, curr *CPUStats) float64 {
	prevIdle := prev.Idle + prev.IOWait
	currIdle := curr.Idle + curr.IOWait

	prevNonIdle := prev.User + prev.Nice + prev.System + prev.IRQ + prev.SoftIRQ + prev.Steal
	currNonIdle := curr.User + curr.Nice + curr.System + curr.IRQ + curr.SoftIRQ + curr.Steal

	prevTotal := prevIdle + prevNonIdle
	currTotal := currIdle + currNonIdle

	totalDiff := currTotal - prevTotal
	idleDiff := currIdle - prevIdle

	if totalDiff == 0 {
		return 0.0
	}

	return (float64(totalDiff-idleDiff) / float64(totalDiff)) * 100.0
}

func (c *cpu) getCpuUsage() (*CPUUsage, error) {
	currStats, err := readCPUStats()
	if err != nil {
		return nil, fmt.Errorf("read CPU stats %w", err)
	}

	usage := calculateCPUUsage(c.prevStats, currStats)

	c.prevStats = currStats

	return &CPUUsage{
		Percentage: usage,
		Timestamp:  time.Now(),
	}, nil
}

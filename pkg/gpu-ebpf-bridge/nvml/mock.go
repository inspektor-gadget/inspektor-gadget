// Copyright 2026 The Inspektor Gadget authors
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

package nvml

import (
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

// Mock is a Poller implementation that fabricates plausible-looking
// telemetry without touching NVML. Used for development on machines
// without an NVIDIA GPU, for CI, and for the bridge's --mode=mock flag.
//
// Per-device snapshots vary sinusoidally over time so a consumer
// scraping the bridge sees values changing (helpful when wiring up
// dashboards or testing freshness logic). Per-process samples are
// produced for a fixed set of synthetic PIDs whose utilization also
// rotates over time.
type Mock struct {
	// NumDevices is the number of fake GPUs to expose. Defaults to 2.
	NumDevices int

	// PidsPerDevice is the number of synthetic processes per device
	// to emit utilization samples for. Defaults to 3.
	PidsPerDevice int

	// FirstPid is the lowest synthetic PID. Subsequent processes get
	// FirstPid+1, FirstPid+2, ... Defaults to 100000 to keep mock PIDs
	// well above the real-PID range on most systems.
	FirstPid uint32

	// Now overrides time.Now() for deterministic testing. nil = real clock.
	Now func() time.Time

	mu    sync.Mutex
	start time.Time
	rng   *rand.Rand
	devs  []DeviceSnapshot
}

func NewMock() *Mock {
	return &Mock{
		NumDevices:    2,
		PidsPerDevice: 3,
		FirstPid:      100000,
	}
}

func (m *Mock) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Mock) Init(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.NumDevices <= 0 {
		m.NumDevices = 2
	}
	if m.PidsPerDevice <= 0 {
		m.PidsPerDevice = 3
	}
	if m.FirstPid == 0 {
		m.FirstPid = 100000
	}
	m.start = m.now()
	m.rng = rand.New(rand.NewPCG(0xdeadbeef, 0x1337))

	// Static per-device properties (size, name) chosen up-front so they
	// don't change between snapshots.
	m.devs = make([]DeviceSnapshot, m.NumDevices)
	for i := range m.devs {
		m.devs[i] = DeviceSnapshot{
			Index:    uint32(i),
			UUID:     "MOCK-" + leftPad(uint64(i), 16),
			Name:     "MOCK GPU model 0",
			MemTotal: 80 * 1024 * 1024 * 1024, // 80 GB
		}
	}
	return nil
}

func (m *Mock) Devices(_ context.Context) ([]DeviceSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.devs == nil {
		return nil, ErrNotAvailable
	}

	now := m.now()
	tsNs := uint64(now.UnixNano())
	elapsed := now.Sub(m.start).Seconds()

	out := make([]DeviceSnapshot, len(m.devs))
	for i, base := range m.devs {
		// Sinusoidal SM utilization with a per-device phase offset, so
		// devices don't all look identical. Period ~60s.
		phase := float64(i) * 0.7
		sm := 50.0 + 45.0*math.Sin(2*math.Pi*elapsed/60+phase)
		mem := 30.0 + 25.0*math.Sin(2*math.Pi*elapsed/45+phase+1.2)

		// VRAM utilization climbs slowly toward ~50% then resets.
		memUsed := uint64(float64(base.MemTotal) * (0.10 + 0.40*math.Mod(elapsed/600, 1.0)))

		out[i] = DeviceSnapshot{
			Index:               base.Index,
			UUID:                base.UUID,
			Name:                base.Name,
			TimestampNs:         tsNs,
			SmUtilPct:           uint32(clamp(sm, 0, 100)),
			MemUtilPct:          uint32(clamp(mem, 0, 100)),
			MemTotal:            base.MemTotal,
			MemUsed:             memUsed,
			MemReserved:         512 * 1024 * 1024,
			TempC:               40 + uint32(elapsed)%40,
			PowerMw:             100000 + uint32(sm*3000),
			SmClockMhz:          1410,
			MemClockMhz:         1593,
			ThrottleReasons:     0,
			PcieTxKbps:          uint64(sm * 10000),
			PcieRxKbps:          uint64(sm * 12000),
			EncUtilPct:          0,
			DecUtilPct:          0,
			NvlinkTxKbps:        0,
			NvlinkRxKbps:        0,
			EccCorrectedTotal:   0,
			EccUncorrectedTotal: 0,
			FanSpeedPct:         30 + uint32(elapsed)%50,
			ComputeMode:         0,
		}
	}
	return out, nil
}

func (m *Mock) ProcessSamples(_ context.Context, lastSeenNs uint64) ([]ProcessSample, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.devs == nil {
		return nil, ErrNotAvailable
	}

	now := m.now()
	tsNs := uint64(now.UnixNano())
	// Mock: always return fresh samples (advance past lastSeenNs).
	if lastSeenNs >= tsNs {
		// Caller asked for samples newer than our clock; nothing to give.
		return nil, nil
	}

	elapsed := now.Sub(m.start).Seconds()
	pid := m.FirstPid

	out := make([]ProcessSample, 0, len(m.devs)*m.PidsPerDevice)
	for _, dev := range m.devs {
		for j := 0; j < m.PidsPerDevice; j++ {
			phase := float64(int(dev.Index)*10+j) * 0.4
			sm := 30.0 + 30.0*math.Sin(2*math.Pi*elapsed/30+phase)
			mem := 20.0 + 15.0*math.Sin(2*math.Pi*elapsed/40+phase+0.5)

			out = append(out, ProcessSample{
				Pid:           pid,
				DeviceIndex:   dev.Index,
				TimestampNs:   tsNs,
				UsedGpuMemory: 256*1024*1024 + uint64(j)*128*1024*1024,
				SmUtilPct:     uint32(clamp(sm, 0, 100)),
				MemUtilPct:    uint32(clamp(mem, 0, 100)),
			})
			pid++
		}
	}
	return out, nil
}

func (m *Mock) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devs = nil
	return nil
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func leftPad(n uint64, width int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	for len(s) < width {
		s = "0" + s
	}
	return s
}

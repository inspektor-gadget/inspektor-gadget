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

package poller_test

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/maps"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/nvml"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/poller"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root for bpffs pin operations")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
}

func pinDirForTest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", "test-poller-"+t.Name())
	t.Cleanup(func() {
		// Best-effort cleanup of any lingering pins.
		for _, name := range []string{
			maps.MapNameMeta, maps.MapNameDevice,
			maps.MapNamePerPid, maps.MapNamePerPidPerDevice,
		} {
			_ = os.Remove(filepath.Join(dir, name))
		}
		_ = os.Remove(dir)
	})
	return dir
}

// TestPollerWritesMockDataToMaps drives the full poll loop with the
// mock NVML backend and verifies that the bridge's pinned maps are
// populated with the synthetic data.
func TestPollerWritesMockDataToMaps(t *testing.T) {
	requireRoot(t)

	pinDir := pinDirForTest(t)
	bridge, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("maps.Open: %v", err)
	}
	t.Cleanup(func() { _ = bridge.Unpin(); _ = bridge.Close() })

	const (
		numDevices    = 2
		pidsPerDevice = 3
	)
	mock := nvml.NewMock()
	mock.NumDevices = numDevices
	mock.PidsPerDevice = pidsPerDevice
	mock.FirstPid = 200000

	p, err := poller.New(poller.Config{
		PollInterval: 50 * time.Millisecond,
		Source:       mock,
		Bridge:       bridge,
	})
	if err != nil {
		t.Fatalf("poller.New: %v", err)
	}

	// Run the poller for 250 ms (≥3 ticks), then cancel.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// gpu_meta: schema_version + n_devices + helper_pid set, fresh.
	metaMap, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNameMeta), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap meta: %v", err)
	}
	defer metaMap.Close()
	var meta maps.Meta
	key0 := uint32(0)
	if err := metaMap.Lookup(&key0, &meta); err != nil {
		t.Fatalf("meta lookup: %v", err)
	}
	if meta.SchemaVersion != maps.SchemaVersion {
		t.Errorf("meta.SchemaVersion: got %d want %d", meta.SchemaVersion, maps.SchemaVersion)
	}
	if meta.N_devices != numDevices {
		t.Errorf("meta.N_devices: got %d want %d", meta.N_devices, numDevices)
	}
	if meta.HelperPid != uint32(os.Getpid()) {
		t.Errorf("meta.HelperPid: got %d want %d", meta.HelperPid, os.Getpid())
	}
	if meta.LastUpdateBoottimeNs == 0 {
		t.Error("meta.LastUpdateBoottimeNs is zero")
	}
	if meta.ClockOffsetNs == 0 {
		t.Error("meta.ClockOffsetNs is zero")
	}

	// gpu_device: each device index should have a non-zero snapshot.
	devMap, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNameDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap device: %v", err)
	}
	defer devMap.Close()
	for idx := uint32(0); idx < numDevices; idx++ {
		var d maps.DeviceMetrics
		if err := devMap.Lookup(&idx, &d); err != nil {
			t.Errorf("device[%d] lookup: %v", idx, err)
			continue
		}
		if d.MemTotal == 0 {
			t.Errorf("device[%d].MemTotal is zero", idx)
		}
		if d.TimestampNs == 0 {
			t.Errorf("device[%d].TimestampNs is zero", idx)
		}
	}

	// gpu_per_pid: expect (numDevices * pidsPerDevice) PIDs starting at
	// mock.FirstPid. Verify each is present.
	perPidMap, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPid), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid: %v", err)
	}
	defer perPidMap.Close()
	expectedPids := numDevices * pidsPerDevice
	for i := uint32(0); i < uint32(expectedPids); i++ {
		pid := mock.FirstPid + i
		var p maps.PidMetricsAggregated
		if err := perPidMap.Lookup(&pid, &p); err != nil {
			t.Errorf("per_pid[%d] lookup: %v", pid, err)
			continue
		}
		if p.TimestampNs == 0 {
			t.Errorf("per_pid[%d].TimestampNs is zero", pid)
		}
		if p.DeviceCount == 0 {
			t.Errorf("per_pid[%d].DeviceCount is zero", pid)
		}
	}

	// gpu_per_pid_per_device: same PIDs but keyed by (pid << 32 | dev).
	// Each PID lives on exactly one mock device, so only one (pid, dev)
	// pair should exist per PID — try the first pid on device 0.
	pddMap, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPidPerDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid_per_device: %v", err)
	}
	defer pddMap.Close()
	firstKey := maps.PerPidPerDeviceKey(mock.FirstPid, 0)
	var pd maps.PidMetrics
	if err := pddMap.Lookup(&firstKey, &pd); err != nil {
		t.Errorf("per_pid_per_device first lookup: %v", err)
	}
}

// TestPollerAggregatesAndFiltersRealisticNvmlNoise drives the poller
// with a tiny in-test source that returns the kind of noisy output
// the real NVML backend exhibits in practice:
//   - pid 0 appearing multiple times per tick (NVML "unattributed
//     work" bucket)
//   - the same (pid, dev) appearing multiple times per tick with
//     varying SM utilization (NVML rolling-window samples)
//
// The poller must:
//  1. drop all pid 0 entries from gpu_per_pid* maps
//  2. fold duplicates and report the max SM/mem
//  3. set DeviceCount to the number of distinct devices, not the
//     number of underlying samples.
func TestPollerAggregatesAndFiltersRealisticNvmlNoise(t *testing.T) {
	requireRoot(t)

	pinDir := pinDirForTest(t)
	bridge, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("maps.Open: %v", err)
	}
	t.Cleanup(func() { _ = bridge.Unpin(); _ = bridge.Close() })

	src := &fakeNvml{
		devs: []nvml.DeviceSnapshot{
			{Index: 0, TimestampNs: 1, MemTotal: 80 << 30, SmUtilPct: 7},
			{Index: 1, TimestampNs: 1, MemTotal: 80 << 30, SmUtilPct: 0},
		},
		samples: []nvml.ProcessSample{
			// pid 0 (NVML "unattributed") returned 5x — must be dropped.
			{Pid: 0, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 1},
			{Pid: 0, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 2},
			{Pid: 0, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 3},
			{Pid: 0, DeviceIndex: 1, TimestampNs: 1, SmUtilPct: 0},
			{Pid: 0, DeviceIndex: 1, TimestampNs: 1, SmUtilPct: 0},
			// Workload PID on dev 0: three samples, max SM is 8.
			{Pid: 1000, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 3, UsedGpuMemory: 2 << 30},
			{Pid: 1000, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 8, UsedGpuMemory: 2 << 30},
			{Pid: 1000, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 5, UsedGpuMemory: 2 << 30},
			// Multi-device PID on dev 0 and dev 1.
			{Pid: 2000, DeviceIndex: 0, TimestampNs: 1, SmUtilPct: 4, UsedGpuMemory: 1 << 30},
			{Pid: 2000, DeviceIndex: 1, TimestampNs: 1, SmUtilPct: 9, UsedGpuMemory: 3 << 30},
		},
	}

	p, err := poller.New(poller.Config{
		PollInterval: 50 * time.Millisecond,
		Source:       src,
		Bridge:       bridge,
	})
	if err != nil {
		t.Fatalf("poller.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	perPid, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPid), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid: %v", err)
	}
	defer perPid.Close()

	// pid 0 must NOT be in the aggregated map.
	pid0 := uint32(0)
	var got maps.PidMetricsAggregated
	if err := perPid.Lookup(&pid0, &got); err == nil {
		t.Errorf("per_pid[0] should be filtered out, got %+v", got)
	}

	// Workload PID: 3 samples folded → SmUtilPctMax=8, DeviceCount=1,
	// UsedGpuMemoryTotal=2 GiB (not summed 3x).
	pid1000 := uint32(1000)
	if err := perPid.Lookup(&pid1000, &got); err != nil {
		t.Fatalf("per_pid[1000] lookup: %v", err)
	}
	if got.SmUtilPctMax != 8 {
		t.Errorf("per_pid[1000].SmUtilPctMax = %d, want 8", got.SmUtilPctMax)
	}
	if got.DeviceCount != 1 {
		t.Errorf("per_pid[1000].DeviceCount = %d, want 1", got.DeviceCount)
	}
	if got.UsedGpuMemoryTotal != 2<<30 {
		t.Errorf("per_pid[1000].UsedGpuMemoryTotal = %d, want %d",
			got.UsedGpuMemoryTotal, uint64(2<<30))
	}
	if got.GpuDevicePrimary != 0 {
		t.Errorf("per_pid[1000].GpuDevicePrimary = %d, want 0", got.GpuDevicePrimary)
	}

	// Multi-device PID: SmUtilPctMax=9, DeviceCount=2,
	// UsedGpuMemoryTotal=4 GiB, GpuDevicePrimary=DevicePrimaryMulti.
	pid2000 := uint32(2000)
	if err := perPid.Lookup(&pid2000, &got); err != nil {
		t.Fatalf("per_pid[2000] lookup: %v", err)
	}
	if got.SmUtilPctMax != 9 {
		t.Errorf("per_pid[2000].SmUtilPctMax = %d, want 9", got.SmUtilPctMax)
	}
	if got.DeviceCount != 2 {
		t.Errorf("per_pid[2000].DeviceCount = %d, want 2", got.DeviceCount)
	}
	if got.UsedGpuMemoryTotal != 4<<30 {
		t.Errorf("per_pid[2000].UsedGpuMemoryTotal = %d, want %d",
			got.UsedGpuMemoryTotal, uint64(4<<30))
	}
	if got.GpuDevicePrimary != maps.DevicePrimaryMulti {
		t.Errorf("per_pid[2000].GpuDevicePrimary = 0x%02x, want 0x%02x",
			got.GpuDevicePrimary, maps.DevicePrimaryMulti)
	}

	// pid 0 must also not appear in per_pid_per_device.
	perPidDev, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPidPerDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid_per_device: %v", err)
	}
	defer perPidDev.Close()
	pid0dev0 := maps.PerPidPerDeviceKey(0, 0)
	var pd maps.PidMetrics
	if err := perPidDev.Lookup(&pid0dev0, &pd); err == nil {
		t.Errorf("per_pid_per_device[0, 0] should be filtered, got %+v", pd)
	}

	// Workload (pid 1000, dev 0): SmUtilPct=8 (max), not 5 (last sample).
	pid1000dev0 := maps.PerPidPerDeviceKey(1000, 0)
	if err := perPidDev.Lookup(&pid1000dev0, &pd); err != nil {
		t.Fatalf("per_pid_per_device[1000, 0] lookup: %v", err)
	}
	if pd.SmUtilPct != 8 {
		t.Errorf("per_pid_per_device[1000,0].SmUtilPct = %d, want 8 (max, not last)",
			pd.SmUtilPct)
	}
	if pd.UsedGpuMemory != 2<<30 {
		t.Errorf("per_pid_per_device[1000,0].UsedGpuMemory = %d, want %d",
			pd.UsedGpuMemory, uint64(2<<30))
	}
}

// fakeNvml is a tiny test-local Poller that returns a fixed set of
// devices and process samples on every tick. Unlike nvml.Mock it does
// not synthesise data; tests put exactly the noise pattern they want
// to exercise into the slices and assert what the poller does with it.
type fakeNvml struct {
	devs    []nvml.DeviceSnapshot
	samples []nvml.ProcessSample
}

func (f *fakeNvml) Init(context.Context) error { return nil }
func (f *fakeNvml) Close() error               { return nil }
func (f *fakeNvml) Devices(context.Context) ([]nvml.DeviceSnapshot, error) {
	return append([]nvml.DeviceSnapshot(nil), f.devs...), nil
}

func (f *fakeNvml) ProcessSamples(context.Context, uint64) ([]nvml.ProcessSample, error) {
	return append([]nvml.ProcessSample(nil), f.samples...), nil
}

// scriptedNvml is a test-local Poller whose ProcessSamples output
// changes per tick: the Nth call returns script[N] (clamped to the last
// entry once the script is exhausted). Lets tests drive PID
// appearance/departure across ticks deterministically.
type scriptedNvml struct {
	devs   []nvml.DeviceSnapshot
	script [][]nvml.ProcessSample
	calls  atomic.Int64
}

func (s *scriptedNvml) Init(context.Context) error { return nil }
func (s *scriptedNvml) Close() error               { return nil }
func (s *scriptedNvml) Devices(context.Context) ([]nvml.DeviceSnapshot, error) {
	return append([]nvml.DeviceSnapshot(nil), s.devs...), nil
}

func (s *scriptedNvml) ProcessSamples(context.Context, uint64) ([]nvml.ProcessSample, error) {
	i := int(s.calls.Add(1)) - 1
	if i >= len(s.script) {
		i = len(s.script) - 1
	}
	return append([]nvml.ProcessSample(nil), s.script[i]...), nil
}

// TestPollerDeletesDepartedPids verifies the stateful delete behaviour
// added with the batch write path: a PID (and its per-(pid, dev) entry)
// present on one tick but gone on the next is deleted from the pinned
// maps, so a dead process can't linger with stale metrics.
func TestPollerDeletesDepartedPids(t *testing.T) {
	requireRoot(t)

	pinDir := pinDirForTest(t)
	bridge, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("maps.Open: %v", err)
	}
	t.Cleanup(func() { _ = bridge.Unpin(); _ = bridge.Close() })

	const activeTs = uint64(123456789)
	src := &scriptedNvml{
		devs: []nvml.DeviceSnapshot{
			{Index: 0, TimestampNs: 1, MemTotal: 80 << 30},
		},
		script: [][]nvml.ProcessSample{
			// tick 0: pid 1 and pid 2 both active on dev 0.
			{
				{Pid: 1, DeviceIndex: 0, TimestampNs: activeTs, SmUtilPct: 50, UsedGpuMemory: 4 << 30},
				{Pid: 2, DeviceIndex: 0, TimestampNs: activeTs, SmUtilPct: 60, UsedGpuMemory: 2 << 30},
			},
			// tick >=1: pid 2 departed; pid 1 remains but is idle
			// (SM==0) while still holding VRAM.
			{
				{Pid: 1, DeviceIndex: 0, TimestampNs: activeTs + 1_000_000, SmUtilPct: 0, UsedGpuMemory: 4 << 30},
			},
		},
	}

	p, err := poller.New(poller.Config{
		PollInterval: 20 * time.Millisecond,
		Source:       src,
		Bridge:       bridge,
	})
	if err != nil {
		t.Fatalf("poller.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := src.calls.Load(); n < 2 {
		t.Fatalf("expected >=2 ticks (active then idle), got %d", n)
	}

	perPid, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPid), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid: %v", err)
	}
	defer perPid.Close()

	// pid 2 departed after tick 0 → must be deleted.
	pid2 := uint32(2)
	var agg maps.PidMetricsAggregated
	if err := perPid.Lookup(&pid2, &agg); err == nil {
		t.Errorf("per_pid[2] should be deleted after departure, got %+v", agg)
	}

	// pid 1 present, idle on the final tick.
	pid1 := uint32(1)
	if err := perPid.Lookup(&pid1, &agg); err != nil {
		t.Fatalf("per_pid[1] lookup: %v", err)
	}
	if agg.SmUtilPctMax != 0 {
		t.Errorf("per_pid[1].SmUtilPctMax = %d, want 0 (idle final tick)", agg.SmUtilPctMax)
	}

	perPidDev, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPidPerDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid_per_device: %v", err)
	}
	defer perPidDev.Close()

	// (pid 2, dev 0) departed → deleted; (pid 1, dev 0) still present.
	key2 := maps.PerPidPerDeviceKey(2, 0)
	var pd maps.PidMetrics
	if err := perPidDev.Lookup(&key2, &pd); err == nil {
		t.Errorf("per_pid_per_device[2,0] should be deleted, got %+v", pd)
	}
	key1 := maps.PerPidPerDeviceKey(1, 0)
	if err := perPidDev.Lookup(&key1, &pd); err != nil {
		t.Errorf("per_pid_per_device[1,0] lookup: %v", err)
	}
}

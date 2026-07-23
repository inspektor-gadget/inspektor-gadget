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

package maps_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/maps"
)

// pinDirForTest returns a unique bpffs subdir per test so parallel runs
// don't stomp on each other (and so a failing test doesn't leak state
// into the next one's pinned map dir).
func pinDirForTest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", "test-"+t.Name())
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root for bpffs pin operations")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}
}

func TestOpenCreatesPinnedMaps(t *testing.T) {
	requireRoot(t)
	pinDir := pinDirForTest(t)

	b, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Unpin(); _ = b.Close() })

	for _, name := range []string{
		maps.MapNameMeta,
		maps.MapNameDevice,
		maps.MapNamePerPid,
		maps.MapNamePerPidPerDevice,
	} {
		path := filepath.Join(pinDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected pin file %s to exist: %v", path, err)
		}
	}
}

func TestUpdateAndLookupMetaDeviceAndPid(t *testing.T) {
	requireRoot(t)
	pinDir := pinDirForTest(t)

	b, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Unpin(); _ = b.Close() })

	// Meta
	wantMeta := maps.Meta{
		SchemaVersion:        maps.SchemaVersion,
		N_devices:            2,
		LastUpdateBoottimeNs: 1234567890,
		HelperPid:            uint32(os.Getpid()),
		ClockOffsetNs:        1_700_000_000_000_000_000,
	}
	if err := b.UpdateMeta(&wantMeta); err != nil {
		t.Fatalf("UpdateMeta: %v", err)
	}

	// Device
	wantDev := maps.DeviceMetrics{
		TimestampNs: 999,
		SmUtilPct:   42,
		MemUtilPct:  17,
		MemTotal:    80 * 1024 * 1024 * 1024,
		MemUsed:     8 * 1024 * 1024 * 1024,
		TempC:       55,
		PowerMw:     250000,
		SmClockMhz:  1410,
	}
	if err := b.UpdateDevice(0, &wantDev); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}

	// Per-PID
	wantPid := maps.PidMetricsAggregated{
		TimestampNs:        1000,
		UsedGpuMemoryTotal: 2 * 1024 * 1024 * 1024,
		SmUtilPctMax:       88,
		MemUtilPctMax:      65,
		GpuDevicePrimary:   0,
		DeviceCount:        1,
	}
	const testPid uint32 = 4242
	if err := b.UpdatePerPid(testPid, &wantPid); err != nil {
		t.Fatalf("UpdatePerPid: %v", err)
	}

	// Per-(PID, device)
	wantPidDev := maps.PidMetrics{
		TimestampNs:   1001,
		UsedGpuMemory: 2 * 1024 * 1024 * 1024,
		SmUtilPct:     88,
		MemUtilPct:    65,
		GpuDevice:     0,
	}
	if err := b.UpdatePerPidPerDevice(testPid, 0, &wantPidDev); err != nil {
		t.Fatalf("UpdatePerPidPerDevice: %v", err)
	}

	// Lookups via a freshly-opened map handle, to prove the data
	// is actually pinned in bpffs (not just held in this process's
	// memory).
	verifyMetaAgainstPin(t, pinDir, wantMeta)
	verifyDeviceAgainstPin(t, pinDir, 0, wantDev)
	verifyPerPidAgainstPin(t, pinDir, testPid, wantPid)
	verifyPerPidPerDeviceAgainstPin(t, pinDir, testPid, 0, wantPidDev)
}

func TestOpenReusesExistingPinnedMaps(t *testing.T) {
	requireRoot(t)
	pinDir := pinDirForTest(t)

	// First open: creates the maps.
	b1, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	wantPid := maps.PidMetricsAggregated{
		TimestampNs:        7,
		UsedGpuMemoryTotal: 1024,
		SmUtilPctMax:       11,
	}
	if err := b1.UpdatePerPid(99, &wantPid); err != nil {
		t.Fatalf("UpdatePerPid: %v", err)
	}
	_ = b1.Close()

	// Second open: must reuse the existing pinned maps. The previously
	// written value must survive.
	b2, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	t.Cleanup(func() { _ = b2.Unpin(); _ = b2.Close() })

	verifyPerPidAgainstPin(t, pinDir, 99, wantPid)
}

func TestUnpinRemovesPinFiles(t *testing.T) {
	requireRoot(t)
	pinDir := pinDirForTest(t)

	b, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Pin files should still be present after Close (Close is not Unpin).
	for _, name := range []string{maps.MapNameMeta, maps.MapNameDevice} {
		path := filepath.Join(pinDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to survive Close: %v", path, err)
		}
	}

	if err := b.Unpin(); err != nil {
		t.Fatalf("Unpin: %v", err)
	}

	for _, name := range []string{
		maps.MapNameMeta, maps.MapNameDevice,
		maps.MapNamePerPid, maps.MapNamePerPidPerDevice,
	} {
		path := filepath.Join(pinDir, name)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected %s to be gone after Unpin, got err=%v", path, err)
		}
	}

	// Unpin is idempotent.
	if err := b.Unpin(); err != nil {
		t.Errorf("Unpin should be idempotent, got: %v", err)
	}
}

// --- helpers that open the pinned maps independently from the Bridge ---

func verifyMetaAgainstPin(t *testing.T, pinDir string, want maps.Meta) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNameMeta), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap meta: %v", err)
	}
	defer m.Close()
	var got maps.Meta
	key := uint32(0)
	if err := m.Lookup(&key, &got); err != nil {
		t.Fatalf("meta lookup: %v", err)
	}
	if got != want {
		t.Errorf("meta: got=%+v want=%+v", got, want)
	}
}

func verifyDeviceAgainstPin(t *testing.T, pinDir string, idx uint32, want maps.DeviceMetrics) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNameDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap device: %v", err)
	}
	defer m.Close()
	var got maps.DeviceMetrics
	if err := m.Lookup(&idx, &got); err != nil {
		t.Fatalf("device lookup: %v", err)
	}
	if got != want {
		t.Errorf("device[%d]: got=%+v want=%+v", idx, got, want)
	}
}

func verifyPerPidAgainstPin(t *testing.T, pinDir string, pid uint32, want maps.PidMetricsAggregated) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPid), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid: %v", err)
	}
	defer m.Close()
	var got maps.PidMetricsAggregated
	if err := m.Lookup(&pid, &got); err != nil {
		t.Fatalf("per_pid lookup: %v", err)
	}
	if got != want {
		t.Errorf("per_pid[%d]: got=%+v want=%+v", pid, got, want)
	}
}

func verifyPerPidPerDeviceAgainstPin(t *testing.T, pinDir string, pid, dev uint32, want maps.PidMetrics) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPidPerDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid_per_device: %v", err)
	}
	defer m.Close()
	var got maps.PidMetrics
	key := maps.PerPidPerDeviceKey(pid, dev)
	if err := m.Lookup(&key, &got); err != nil {
		t.Fatalf("per_pid_per_device lookup: %v", err)
	}
	if got != want {
		t.Errorf("per_pid_per_device[%d:%d]: got=%+v want=%+v", pid, dev, got, want)
	}
}

func requirePerPidAbsent(t *testing.T, pinDir string, pid uint32) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPid), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid: %v", err)
	}
	defer m.Close()
	var got maps.PidMetricsAggregated
	if err := m.Lookup(&pid, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("per_pid[%d]: expected ErrKeyNotExist, got err=%v value=%+v", pid, err, got)
	}
}

func requirePerPidPerDeviceAbsent(t *testing.T, pinDir string, key uint64) {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, maps.MapNamePerPidPerDevice), nil)
	if err != nil {
		t.Fatalf("LoadPinnedMap per_pid_per_device: %v", err)
	}
	defer m.Close()
	var got maps.PidMetrics
	if err := m.Lookup(&key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("per_pid_per_device[%d]: expected ErrKeyNotExist, got err=%v value=%+v", key, err, got)
	}
}

func TestBatchUpdateAndDelete(t *testing.T) {
	requireRoot(t)
	pinDir := pinDirForTest(t)

	b, err := maps.Open(pinDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Unpin(); _ = b.Close() })

	// --- aggregated per-PID ---
	pids := []uint32{101, 102, 103}
	vals := []maps.PidMetricsAggregated{
		{TimestampNs: 1, UsedGpuMemoryTotal: 1 << 20, SmUtilPctMax: 10, DeviceCount: 1},
		{TimestampNs: 2, UsedGpuMemoryTotal: 2 << 20, SmUtilPctMax: 20, DeviceCount: 1},
		{TimestampNs: 3, UsedGpuMemoryTotal: 3 << 20, SmUtilPctMax: 30, DeviceCount: 1},
	}
	if n, err := b.BatchUpdatePerPid(pids, vals); err != nil {
		t.Fatalf("BatchUpdatePerPid: %v (n=%d)", err, n)
	}
	for i, pid := range pids {
		verifyPerPidAgainstPin(t, pinDir, pid, vals[i])
	}

	// Length mismatch must be rejected without touching the map.
	if _, err := b.BatchUpdatePerPid(pids, vals[:1]); err == nil {
		t.Error("BatchUpdatePerPid with mismatched lengths: expected error, got nil")
	}

	// Delete a subset; the survivor must remain.
	if _, err := b.BatchDeletePerPid([]uint32{101, 103}); err != nil {
		t.Fatalf("BatchDeletePerPid: %v", err)
	}
	requirePerPidAbsent(t, pinDir, 101)
	requirePerPidAbsent(t, pinDir, 103)
	verifyPerPidAgainstPin(t, pinDir, 102, vals[1])

	// Deleting an absent key is not an error.
	if _, err := b.BatchDeletePerPid([]uint32{999999}); err != nil {
		t.Errorf("BatchDeletePerPid absent key: %v", err)
	}

	// --- per-(PID, device) ---
	keys := []uint64{
		maps.PerPidPerDeviceKey(201, 0),
		maps.PerPidPerDeviceKey(201, 1),
		maps.PerPidPerDeviceKey(202, 0),
	}
	pdVals := []maps.PidMetrics{
		{TimestampNs: 10, UsedGpuMemory: 1 << 20, SmUtilPct: 1, GpuDevice: 0},
		{TimestampNs: 11, UsedGpuMemory: 2 << 20, SmUtilPct: 2, GpuDevice: 1},
		{TimestampNs: 12, UsedGpuMemory: 3 << 20, SmUtilPct: 3, GpuDevice: 0},
	}
	if _, err := b.BatchUpdatePerPidPerDevice(keys, pdVals); err != nil {
		t.Fatalf("BatchUpdatePerPidPerDevice: %v", err)
	}
	verifyPerPidPerDeviceAgainstPin(t, pinDir, 201, 0, pdVals[0])
	verifyPerPidPerDeviceAgainstPin(t, pinDir, 201, 1, pdVals[1])
	verifyPerPidPerDeviceAgainstPin(t, pinDir, 202, 0, pdVals[2])

	if _, err := b.BatchDeletePerPidPerDevice([]uint64{keys[0], keys[2]}); err != nil {
		t.Fatalf("BatchDeletePerPidPerDevice: %v", err)
	}
	requirePerPidPerDeviceAbsent(t, pinDir, keys[0])
	requirePerPidPerDeviceAbsent(t, pinDir, keys[2])
	verifyPerPidPerDeviceAgainstPin(t, pinDir, 201, 1, pdVals[1])

	// Empty batches are no-ops.
	if n, err := b.BatchUpdatePerPid(nil, nil); err != nil || n != 0 {
		t.Errorf("BatchUpdatePerPid empty: n=%d err=%v", n, err)
	}
	if n, err := b.BatchDeletePerPid(nil); err != nil || n != 0 {
		t.Errorf("BatchDeletePerPid empty: n=%d err=%v", n, err)
	}
}

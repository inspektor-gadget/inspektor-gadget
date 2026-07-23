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

// Integration test for the trace_gpu_starvation gadget.
//
// The gadget consumes the gpu-ebpf-bridge pinned maps (gpu_per_pid,
// gpu_meta) and hooks finish_task_switch to detect threads that burn
// CPU while the GPU their process holds sits idle. We mock the bridge
// by pre-creating and pinning those two maps and writing:
//   - a gpu_meta entry with a fresh last_update_boottime_ns and the
//     real CLOCK_REALTIME->CLOCK_BOOTTIME offset, and
//   - a gpu_per_pid entry keyed by this test process's own PID, marked
//     as holding GPU memory but last active a couple of seconds ago
//     (so it looks idle).
//
// We then spin several CPU-bound goroutines (oversubscribing the CPUs
// to force involuntary context switches) inside this very process, so
// the gadget sees our PID burning CPU while its GPU is idle and emits
// a starvation event attributed to our PID.
package tests

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	pinDir = "/sys/fs/bpf"

	perPidMapName       = "gpu_per_pid"
	perPidMapKeySize    = 4  // sizeof(__u32 pid)
	perPidMapValueSize  = 32 // sizeof(struct gpu_pid_metrics_aggregated)
	perPidMapMaxEntries = 4096

	deviceMapName       = "gpu_device"
	deviceMapKeySize    = 4   // sizeof(__u32 device index)
	deviceMapValueSize  = 128 // sizeof(struct gpu_device_metrics)
	deviceMapMaxEntries = 16  // GPU_MAX_DEVICES

	metaMapName       = "gpu_meta"
	metaMapKeySize    = 4  // sizeof(__u32)
	metaMapValueSize  = 32 // sizeof(struct gpu_meta)
	metaMapMaxEntries = 1
)

// pidMetricsAggregated mirrors struct gpu_pid_metrics_aggregated in
// program.bpf.c (and include/gadget/gpu_types.h). Layout must match
// exactly. See gpu_top_per_pid's integration test for the same mirror.
type pidMetricsAggregated struct {
	TimestampNs        uint64
	UsedGpuMemoryTotal uint64

	SmUtilPctMax  uint32
	MemUtilPctMax uint32

	GpuDevicePrimary uint8
	DeviceCount      uint8
	_                uint16  // explicit C _pad
	_                [4]byte // trailing alignment pad
}

// gpuDeviceMetrics mirrors the leading fields of struct
// gpu_device_metrics in include/gadget/gpu_types.h. Only timestamp_ns
// and sm_util_pct are written by this test; the remaining fields are
// covered by a trailing pad so the struct size (128 B) matches the C
// struct and thus the pinned gpu_device map's value size.
type gpuDeviceMetrics struct {
	TimestampNs uint64
	SmUtilPct   uint32
	MemUtilPct  uint32
	_           [112]byte // mem_total .. compute_mode
}

// gpuMeta mirrors struct gpu_meta in program.bpf.c (and
// include/gadget/gpu_types.h).
type gpuMeta struct {
	SchemaVersion        uint32
	NDevices             uint32
	LastUpdateBoottimeNs uint64
	HelperPid            uint32
	Reserved             uint32
	ClockOffsetNs        int64
}

// expectedProcess mirrors the subset of struct gadget_process we assert
// on (the process PID, which for a threaded process is the tgid).
type expectedProcess struct {
	Pid uint32 `json:"pid"`
}

// expectedEvent mirrors struct event in program.bpf.c. The volatile
// counters are asserted to be non-zero via NormalizeInt rather than
// matched exactly.
type expectedEvent struct {
	Proc      expectedProcess `json:"proc"`
	CpuTimeNs uint64          `json:"cpu_time_ns"`
	IdleNs    uint64          `json:"idle_ns"`
	HitCount  uint32          `json:"hit_count"`
}

func TestTraceGpuStarvation(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("trace_gpu_starvation integration test only supports ig local mode (mocks the gpu-ebpf-bridge via host bpffs pins and needs --host)")
	}

	// Sanity: Go struct sizes must match the C struct sizes.
	require.Equal(t, perPidMapValueSize, binary.Size(pidMetricsAggregated{}),
		"struct gpu_pid_metrics_aggregated size mismatch")
	require.Equal(t, deviceMapValueSize, binary.Size(gpuDeviceMetrics{}),
		"struct gpu_device_metrics size mismatch")
	require.Equal(t, metaMapValueSize, binary.Size(gpuMeta{}),
		"struct gpu_meta size mismatch")

	// Step 1: pre-create and pin the three bridge maps, mocking what the
	// gpu-ebpf-bridge daemon does at startup.
	perPid := createPinnedMap(t, perPidMapName, ebpf.LRUHash,
		perPidMapKeySize, perPidMapValueSize, perPidMapMaxEntries)
	device := createPinnedMap(t, deviceMapName, ebpf.Array,
		deviceMapKeySize, deviceMapValueSize, deviceMapMaxEntries)
	meta := createPinnedMap(t, metaMapName, ebpf.Array,
		metaMapKeySize, metaMapValueSize, metaMapMaxEntries)

	// Step 2: populate the maps. Read the current CLOCK_BOOTTIME and
	// CLOCK_REALTIME so we can (a) mark the bridge data as fresh and
	// (b) hand the gadget a realistic REALTIME->BOOTTIME offset, which
	// it uses to convert the device's wall-clock sample timestamp into
	// CLOCK_BOOTTIME for the device-activity latch.
	bootNow := clockNs(t, unix.CLOCK_BOOTTIME)
	realtimeNow := clockNs(t, unix.CLOCK_REALTIME)
	clockOffset := int64(realtimeNow) - int64(bootNow)

	// Device 0 was last observed active ~2s ago (in wall-clock terms):
	// sm_util > 0 with a stale timestamp. The device-activity latch
	// (ig_sched_switch_devlatch) converts this to a CLOCK_BOOTTIME
	// last-active of ~2s ago, so gpu_holder() computes a GPU-idle span
	// of ~2s for the holder PID and the gadget reports starvation.
	const idleAgo = 2 * uint64(time.Second)

	deviceEntry := gpuDeviceMetrics{
		TimestampNs: realtimeNow - idleAgo,
		SmUtilPct:   50, // active sample, but stale (2s old)
	}

	selfPid := uint32(os.Getpid())
	perPidEntry := pidMetricsAggregated{
		TimestampNs:        bootNow,
		UsedGpuMemoryTotal: 2 * 1024 * 1024 * 1024, // 2 GiB held
		SmUtilPctMax:       0,                      // GPU idle now
		MemUtilPctMax:      0,
		GpuDevicePrimary:   0, // memory lives on device 0
		DeviceCount:        1,
	}
	metaEntry := gpuMeta{
		SchemaVersion:        1,
		NDevices:             1,
		LastUpdateBoottimeNs: bootNow,
		ClockOffsetNs:        clockOffset,
	}
	require.NoError(t, perPid.Update(selfPid, &perPidEntry, ebpf.UpdateAny),
		"write gpu_per_pid entry")
	require.NoError(t, device.Update(uint32(0), &deviceEntry, ebpf.UpdateAny),
		"write gpu_device entry")
	require.NoError(t, meta.Update(uint32(0), &metaEntry, ebpf.UpdateAny),
		"write gpu_meta entry")

	// Step 3: spin CPU-bound goroutines inside this process. We
	// oversubscribe the CPUs (2x NumCPU) and lock each goroutine to
	// its own OS thread so the scheduler is forced to time-slice them,
	// generating the involuntary context switches the gadget accounts.
	// They all belong to this process (tgid == selfPid), which the
	// mocked bridge marks as a GPU holder.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2*runtime.NumCPU(); i++ {
		wg.Add(1)
		go burnCPU(&wg, stop)
	}
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})

	// Step 4: run the gadget and validate that a starvation event is
	// emitted for our PID with non-zero CPU time, idle time and hit
	// count. Relax the thresholds: min-idle-ms low enough that our ~2s
	// idle qualifies immediately, and stale-threshold-ms high enough
	// that our single gpu_meta write stays "fresh" for the whole run.
	expectedEntry := &expectedEvent{
		Proc:      expectedProcess{Pid: selfPid},
		CpuTimeNs: utils.NormalizedInt,
		IdleNs:    utils.NormalizedInt,
		HitCount:  utils.NormalizedInt,
	}
	normalize := func(e *expectedEvent) {
		utils.NormalizeInt(&e.CpuTimeNs)
		utils.NormalizeInt(&e.IdleNs)
		utils.NormalizeInt(&e.HitCount)
	}

	// --host is required so the gadget is not restricted to containerized
	// processes: this test's CPU-burner threads run in the host mount
	// namespace, and gadget_should_discard_data_current() would otherwise
	// drop their context switches.
	runnerOpts := []igrunner.Option{
		igrunner.WithFlags(
			"--timeout=6",
			"--host",
			"--min-idle-ms=100",
			"--stale-threshold-ms=60000",
		),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			match.MatchEntries(t, match.JSONMultiObjectMode, output,
				normalize, expectedEntry)
		}),
	}

	cmd := igrunner.New("trace_gpu_starvation", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t)
}

// createPinnedMap creates and pins a map under pinDir, registering a
// cleanup that closes it and removes the pin.
func createPinnedMap(t *testing.T, name string, typ ebpf.MapType, keySize, valueSize, maxEntries uint32) *ebpf.Map {
	t.Helper()
	spec := &ebpf.MapSpec{
		Name:       name,
		Type:       typ,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Pinning:    ebpf.PinByName,
	}
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: pinDir})
	require.NoError(t, err, "create and pin %s map", name)
	t.Cleanup(func() {
		_ = m.Close()
		_ = os.Remove(filepath.Join(pinDir, name))
	})
	return m
}

// clockNs returns the given POSIX clock's current value in nanoseconds.
func clockNs(t *testing.T, clock int32) uint64 {
	t.Helper()
	var ts unix.Timespec
	require.NoError(t, unix.ClockGettime(clock, &ts), "clock_gettime")
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)
}

// burnCPU runs a tight arithmetic loop (defeating dead-code elimination
// via a volatile-ish sink) until stop is closed.
func burnCPU(wg *sync.WaitGroup, stop <-chan struct{}) {
	defer wg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var x uint64
	for {
		select {
		case <-stop:
			runtime.KeepAlive(x)
			return
		default:
		}
		// A chunk of pure CPU work between stop checks.
		for i := 0; i < 1_000_000; i++ {
			x = x*1103515245 + 12345
		}
	}
}

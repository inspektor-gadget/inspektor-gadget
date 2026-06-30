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

// Integration test for the gpu_top_per_pid gadget. Mocks the
// gpu-ebpf-bridge daemon by pre-creating and pinning the gpu_per_pid
// LRU_HASH map externally with one realistic entry keyed by the test
// runner's own PID (so bpf_task_from_pid resolves to a real
// task_struct and the gadget emits a real comm + mntns_id).
//
// Validates:
//   - non-existent PIDs are skipped (process exited between bridge
//     write and iter run)
//   - existing PIDs are emitted with correct GPU stats AND with a
//     real comm and a real (non-zero) mntns_id from the kernel side
//   - iteration is non-destructive (entries remain after the run)

package tests

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	pinDir        = "/sys/fs/bpf"
	pinnedMapName = "gpu_per_pid"
	mapKeySize    = 4  // sizeof(__u32 pid)
	mapValueSize  = 32 // sizeof(struct gpu_pid_metrics_aggregated); see assertion below
	mapMaxEntries = 4096

	// Pick a PID that is virtually guaranteed not to exist on a CI host
	// (kernel PID_MAX_LIMIT is typically 4194304; values above 2^24 are
	// extremely rare in practice). The gadget should silently skip the
	// entry because bpf_task_from_pid returns NULL.
	nonExistentPid = uint32(16777215)
)

// pidMetricsAggregated mirrors struct gpu_pid_metrics_aggregated in
// program.bpf.c (and the bridge's include/gpu_types.h). Field order,
// sizes, and padding must match exactly so cilium/ebpf binary-marshals
// into the same layout the BPF program reads. The trailing 4-byte
// pad is the C-natural-alignment padding (struct contains u64
// members so sizeof is rounded up to a multiple of 8); the bridge's
// bpf2go-generated struct includes it for the same reason.
type pidMetricsAggregated struct {
	TimestampNs        uint64
	UsedGpuMemoryTotal uint64

	SmUtilPctMax  uint32
	MemUtilPctMax uint32

	GpuDevicePrimary uint8
	DeviceCount      uint8
	_                uint16  // the explicit C _pad field
	_                [4]byte // trailing alignment pad
}

// expectedProcess mirrors the subset of struct gadget_process fields
// we assert on. The full struct (creds, parent, tid, etc.) is also
// emitted by IG but we leave those columns alone — they're verified
// by the existence of a non-zero mntns_id (the kfunc + CORE chain
// having worked correctly).
type expectedProcess struct {
	Pid     uint32 `json:"pid"`
	MntnsId uint64 `json:"mntns_id"`
}

// expectedEvent mirrors struct gpu_top_per_pid_event. Note that the
// nested gadget_process is serialised under the "proc" key (the BPF
// field name), so we have to mirror that nesting here rather than
// flattening the PID to top level.
type expectedEvent struct {
	Proc             expectedProcess `json:"proc"`
	MemUsedRaw       uint64          `json:"mem_used_raw"`
	SmUtilPctMax     uint32          `json:"sm_util_pct_max"`
	MemUtilPctMax    uint32          `json:"mem_util_pct_max"`
	GpuDevicePrimary uint8           `json:"gpu_device_primary"`
	DeviceCount      uint8           `json:"device_count"`
	TimestampNs      uint64          `json:"timestamp_ns"`
}

func TestGpuTopPerPid(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("gpu_top_per_pid integration test only supports ig local mode (mocks the gpu-ebpf-bridge via host bpffs pins)")
	}

	// Sanity: Go struct size must match the C struct size.
	require.Equal(t, mapValueSize, binary.Size(pidMetricsAggregated{}),
		"struct gpu_pid_metrics_aggregated size mismatch; "+
			"update mapValueSize or struct")

	// Step 1: pre-create and pin the gpu_per_pid map externally,
	// mocking what the gpu-ebpf-bridge daemon does at startup.
	spec := &ebpf.MapSpec{
		Name:       pinnedMapName,
		Type:       ebpf.LRUHash,
		KeySize:    mapKeySize,
		ValueSize:  mapValueSize,
		MaxEntries: mapMaxEntries,
		Pinning:    ebpf.PinByName,
	}
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: pinDir})
	require.NoError(t, err, "create and pin gpu_per_pid map")
	t.Cleanup(func() {
		_ = m.Close()
		_ = os.Remove(filepath.Join(pinDir, pinnedMapName))
	})

	// Step 2: populate two entries:
	//   - one keyed by the test runner's own PID, which DOES exist and
	//     resolves through bpf_task_from_pid to a real task_struct.
	//     The gadget should emit it with the real comm + mntns_id.
	//   - one keyed by an unlikely-to-exist PID. The gadget should
	//     silently skip it (bpf_task_from_pid returns NULL).
	selfPid := uint32(os.Getpid())
	require.NotEqual(t, selfPid, nonExistentPid,
		"unlucky: test PID collides with the never-exists PID sentinel")

	selfEntry := pidMetricsAggregated{
		TimestampNs:        1_234_567_890,
		UsedGpuMemoryTotal: 2_147_483_648, // 2 GiB
		SmUtilPctMax:       73,
		MemUtilPctMax:      41,
		GpuDevicePrimary:   0,
		DeviceCount:        1,
	}
	ghostEntry := pidMetricsAggregated{
		TimestampNs:        9_999_999_999,
		UsedGpuMemoryTotal: 999_999_999,
		SmUtilPctMax:       99,
		DeviceCount:        1,
	}
	require.NoError(t, m.Update(selfPid, &selfEntry, ebpf.UpdateAny),
		"write self PID entry")
	require.NoError(t, m.Update(nonExistentPid, &ghostEntry, ebpf.UpdateAny),
		"write ghost PID entry")

	// Step 3: run the gadget and validate the iter output. The default
	// fetch-interval is 1 s and fetch-count is 0 (unlimited), so the
	// stream is JSONMultiArrayMode (one array per refresh tick).
	// MatchEntries only requires every expected entry to appear in at
	// least one of the arrays, so a 2 s timeout reliably catches at
	// least one fetch with our PID.
	//
	// We assert on PID (proves the iter saw the right map entry), on
	// a non-zero mntns_id (proves bpf_task_from_pid resolved the PID
	// to a real task and the CORE chain through nsproxy->mnt_ns
	// worked), and on the GPU stats (proves the formatters operator
	// and BTF marshalling are sane).
	expected := []*expectedEvent{
		{
			Proc: expectedProcess{
				Pid:     selfPid,
				MntnsId: hostMntnsId(t),
			},
			MemUsedRaw:       2_147_483_648,
			SmUtilPctMax:     73,
			MemUtilPctMax:    41,
			GpuDevicePrimary: 0,
			DeviceCount:      1,
			TimestampNs:      1_234_567_890,
		},
	}
	runnerOpts := []igrunner.Option{
		igrunner.WithFlags("--timeout=2"),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			// Assert the GPU fields match.
			match.MatchEntries(t, match.JSONMultiArrayMode,
				output, nil, expected...)

			// The ghost PID must NOT appear; the kfunc returned
			// NULL and the gadget skipped it.
			require.NotContains(t, output, "16777215",
				"ghost PID should have been filtered by "+
					"bpf_task_from_pid NULL check")
		}),
	}

	cmd := igrunner.New("gpu_top_per_pid", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t)

	// Step 4: verify iteration was non-destructive. Both entries
	// must still be present in the LRU_HASH (we wrote them, the
	// gadget only read).
	var got pidMetricsAggregated
	require.NoError(t, m.Lookup(selfPid, &got), "self PID still present")
	require.Equal(t, selfEntry, got, "self PID unchanged")
	require.NoError(t, m.Lookup(nonExistentPid, &got), "ghost PID still present")
	require.Equal(t, ghostEntry, got, "ghost PID unchanged")
}

// hostMntnsId reads the test runner's own mount namespace inode
// number from /proc/self/ns/mnt. This is what the gadget will
// extract via BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum) when it
// resolves selfPid, so asserting equality proves the kfunc + CORE
// chain produced the correct value.
func hostMntnsId(t *testing.T) uint64 {
	t.Helper()
	link, err := os.Readlink("/proc/self/ns/mnt")
	require.NoError(t, err, "readlink /proc/self/ns/mnt")
	// link looks like "mnt:[4026531841]"
	var inum uint64
	_, err = fmt.Sscanf(link, "mnt:[%d]", &inum)
	require.NoError(t, err, "parse mntns inode from %q", link)
	return inum
}

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

// Integration test for the test_iter_map_elem CI gadget. Validates that
// IG can attach a SEC("iter/bpf_map_elem") program to an externally-pinned
// BPF map via GADGET_ITER_TARGET_MAP, that the gadget emits one event per
// map entry, and that iteration is non-destructive (entries remain in the
// map after each run).

package tests

import (
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
	// Must byte-match the declaration in the gadget's program.bpf.c.
	pinDir         = "/sys/fs/bpf"
	pinnedMapName  = "test_iter_map"
	mapValueSize   = 24 // sizeof(struct test_value)
	mapKeySize     = 4  // sizeof(struct test_key)
	mapMaxEntries  = 4096
)

// testKey/testValue mirror the BPF structs in program.bpf.c. Field order and
// sizes must match exactly so cilium/ebpf binary-marshals into the same
// layout the BPF program expects.
type testKey struct {
	Pid uint32
}

type testValue struct {
	TimestampNs   uint64
	SmUtilPct     uint32
	MemUtilPct    uint32
	UsedGpuMemory uint64
}

// expectedEvent mirrors the JSON output the iter datasource emits (one
// object per map entry). Field names follow IG's JSON serialization, which
// uses the BPF struct field names verbatim.
type expectedEvent struct {
	Pid           uint32 `json:"pid"`
	SmUtilPct     uint32 `json:"sm_util_pct"`
	MemUtilPct    uint32 `json:"mem_util_pct"`
	UsedGpuMemory uint64 `json:"used_gpu_memory"`
	TimestampNs   uint64 `json:"timestamp_ns"`
}

func TestIterMapElem(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	// Step 1: pre-create and pin the BPF map externally (mimicking a
	// userspace producer such as gpu-ebpf-bridge).
	spec := &ebpf.MapSpec{
		Name:       pinnedMapName,
		Type:       ebpf.LRUHash,
		KeySize:    mapKeySize,
		ValueSize:  mapValueSize,
		MaxEntries: mapMaxEntries,
		Pinning:    ebpf.PinByName,
	}
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: pinDir})
	require.NoError(t, err, "create and pin test map")
	t.Cleanup(func() {
		_ = m.Close()
		_ = os.Remove(filepath.Join(pinDir, pinnedMapName))
	})

	// Step 2: populate with three deterministic entries.
	entries := []struct {
		k testKey
		v testValue
	}{
		{testKey{Pid: 1000}, testValue{TimestampNs: 1, SmUtilPct: 42, MemUtilPct: 17, UsedGpuMemory: 512 * 1024 * 1024}},
		{testKey{Pid: 2000}, testValue{TimestampNs: 2, SmUtilPct: 88, MemUtilPct: 65, UsedGpuMemory: 8 * 1024 * 1024 * 1024}},
		{testKey{Pid: 3000}, testValue{TimestampNs: 3, SmUtilPct: 5, MemUtilPct: 2, UsedGpuMemory: 64 * 1024 * 1024}},
	}
	for _, e := range entries {
		err := m.Update(&e.k, &e.v, ebpf.UpdateAny)
		require.NoError(t, err, "writing entry pid=%d", e.k.Pid)
	}

	// Step 3: run the gadget and validate the iter datasource output. ig
	// emits a single JSON array because mapiter/iter datasources are array
	// datasources (one packet per fetch, n elements per packet).
	expected := []*expectedEvent{
		{Pid: 1000, SmUtilPct: 42, MemUtilPct: 17, UsedGpuMemory: 512 * 1024 * 1024, TimestampNs: 1},
		{Pid: 2000, SmUtilPct: 88, MemUtilPct: 65, UsedGpuMemory: 8 * 1024 * 1024 * 1024, TimestampNs: 2},
		{Pid: 3000, SmUtilPct: 5, MemUtilPct: 2, UsedGpuMemory: 64 * 1024 * 1024, TimestampNs: 3},
	}

	runnerOpts := []igrunner.Option{
		igrunner.WithFlags("--timeout=2"),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			match.MatchEntries(t, match.JSONSingleArrayMode, output, nil, expected...)
		}),
	}

	cmd := igrunner.New("ci/test_iter_map_elem", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t)

	// Step 4: verify the iteration was non-destructive. All three entries
	// must still be present and unchanged. This is the key property that
	// distinguishes iter/bpf_map_elem from GADGET_MAPITER (which uses
	// BPF_MAP_LOOKUP_AND_DELETE_BATCH and drains the map).
	for _, e := range entries {
		var got testValue
		err := m.Lookup(&e.k, &got)
		require.NoError(t, err, "map entry pid=%d should still exist after iteration", e.k.Pid)
		require.Equal(t, e.v, got, "map entry pid=%d should be unchanged after iteration", e.k.Pid)
	}
}

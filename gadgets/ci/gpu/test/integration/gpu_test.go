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

// End-to-end integration test for the gpu-ebpf-bridge four-map
// contract: launches a pre-built gpu-ebpf-bridge binary as a
// subprocess in --mode=mock, waits for the pinned maps to appear,
// runs the ci/gpu gadget, and asserts the emitted events match
// the mock backend's deterministic properties.
//
// The bridge binary is not built by this test. Its path must be
// provided via the GPU_EBPF_BRIDGE_PATH environment variable
// (mirroring the IG_PATH pattern for the ig binary). The caller
// (gadgets/Makefile / the CI workflow) is responsible for building
// gpu-ebpf-bridge and passing the path.
//
// Tests the ig-local path only (see t.Skip below). The k8s path
// (kubectl-gadget deploy) is not supported: kubectl-gadget's
// baked-in manifests do not include the bridge sidecar (which is
// only added via the helm chart), so the maps are not present in
// bpffs.

package tests

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	pinDir      = "/sys/fs/bpf"
	mapNameMeta = "gpu_meta"
)

// gpuEvent mirrors struct gpu_event in program.bpf.c.
type gpuEvent struct {
	Device      uint32 `json:"device"`
	SmUtilPct   uint32 `json:"sm_util_pct"`
	MemUtilPct  uint32 `json:"mem_util_pct"`
	TempC       uint32 `json:"temp_c"`
	PowerMw     uint32 `json:"power_mw"`
	MemUsed     uint64 `json:"mem_used"`
	MemTotal    uint64 `json:"mem_total"`
	TimestampNs uint64 `json:"timestamp_ns"`
}

func TestCiGpu(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	bridgePath := gadgettesting.RequireGpuEbpfBridge(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("ci/gpu test requires launching gpu-ebpf-bridge as a subprocess; only supported in ig local mode")
	}

	t.Logf("using bridge binary at %s", bridgePath)

	// Ensure the target maps are not left over from a previous run.
	// The bridge would happily reuse them, but stale data would
	// break assertions.
	unpinBridgeMaps(t)

	// Start the bridge subprocess with a fast poll interval so data
	// arrives quickly. --keep-pins=false (default) so it cleans up
	// on shutdown.
	cmd := exec.Command(bridgePath,
		"--mode=mock",
		"--pin-dir="+pinDir,
		"--poll-interval=100ms",
		"--log-level=info",
	)
	// SIGINT the bridge via its own process group on cleanup so
	// signal handling works cleanly (SIGINT -> poll loop exit ->
	// maps unpin -> process exit).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = &testWriter{t: t, prefix: "bridge:stdout"}
	cmd.Stderr = &testWriter{t: t, prefix: "bridge:stderr"}
	require.NoError(t, cmd.Start(), "start bridge")
	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("bridge did not exit on SIGINT within 5s; sending SIGKILL")
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		// Best-effort: ensure maps are gone even if the bridge
		// crashed before unpinning.
		unpinBridgeMaps(t)
	})

	// Wait for the bridge to populate its maps. The mock backend
	// takes one poll tick (~100ms) to write the first data; give
	// it generous headroom for slow CI.
	waitForMap(t, filepath.Join(pinDir, mapNameMeta), 10*time.Second)

	// Run the ci/gpu gadget and validate that the two devices the
	// mock backend produces are emitted with sensible properties.
	runnerOpts := []igrunner.Option{
		igrunner.WithFlags("--timeout=2"),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			validateDeviceEntries(t, output)
		}),
	}

	runner := igrunner.New("ci/gpu", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{runner}, t)
}

func unpinBridgeMaps(t *testing.T) {
	t.Helper()
	for _, name := range []string{"gpu_meta", "gpu_device", "gpu_per_pid", "gpu_per_pid_per_device"} {
		path := filepath.Join(pinDir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Logf("removing %s: %v", path, err)
		}
	}
}

func waitForMap(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("map %s did not appear within %s", path, timeout)
}

// validateDeviceEntries asserts on the deterministic properties of
// the mock backend's output: 1-16 devices, each with
// MemTotal = 80 GiB, timestamp_ns > 0, distinct device indices.
// Uses a custom matcher rather than match.MatchEntries because the
// time-varying utilization fields (SmUtilPct etc.) can't be pinned
// to specific values.
func validateDeviceEntries(t *testing.T, output string) {
	t.Helper()

	events := parseFirstJSONArray(t, output)
	require.GreaterOrEqual(t, len(events), 1, "expected at least one device event")
	require.LessOrEqual(t, len(events), 16, "expected at most GPU_MAX_DEVICES=16 events")

	seenDevices := map[uint32]bool{}
	const mockMemTotal uint64 = 80 * 1024 * 1024 * 1024

	for _, ev := range events {
		require.False(t, seenDevices[ev.Device],
			"device %d appeared twice in a single iteration", ev.Device)
		seenDevices[ev.Device] = true

		require.Less(t, ev.Device, uint32(16), "device index out of range")
		require.Equal(t, mockMemTotal, ev.MemTotal,
			"mock backend should report MemTotal=80GiB for device %d", ev.Device)
		require.NotZero(t, ev.TimestampNs,
			"filtered-out slots should not have been emitted (timestamp_ns=0)")
	}
}

// parseFirstJSONArray finds the first line in output that starts
// with '[' and parses it as a JSON array of gpuEvent.
func parseFirstJSONArray(t *testing.T, output string) []gpuEvent {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		var events []gpuEvent
		if err := json.Unmarshal([]byte(line), &events); err != nil {
			t.Logf("skipping unparseable line: %v", err)
			continue
		}
		return events
	}
	t.Fatalf("no JSON array found in gadget output:\n%s", output)
	return nil
}

// testWriter forwards subprocess output to t.Log with a prefix.
type testWriter struct {
	t      *testing.T
	prefix string
}

func (w *testWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg == "" {
		return len(p), nil
	}
	w.t.Logf("[%s] %s", w.prefix, msg)
	return len(p), nil
}

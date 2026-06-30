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

// Integration test for the gpu_top gadget. This test mocks the
// gpu-ebpf-bridge daemon by pre-creating and pinning the gpu_device
// ARRAY map externally with realistic values, then runs gpu_top and
// validates:
//
//   - Only slots with timestamp_ns != 0 are emitted (active devices).
//   - All telemetry fields are correctly propagated through the iter
//     program into the event datasource.
//   - Iteration is non-destructive (the map is unchanged afterwards).

package tests

import (
	"encoding/binary"
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
	pinnedMapName = "gpu_device"
	mapKeySize    = 4   // sizeof(u32)
	mapValueSize  = 128 // sizeof(struct gpu_device_metrics); see assertion below
	mapMaxEntries = 16  // GPU_MAX_DEVICES
)

// gpuDeviceMetrics mirrors struct gpu_device_metrics in program.bpf.c
// (and the bridge's include/gpu_types.h). Field order, sizes, and
// padding must match exactly so cilium/ebpf binary-marshals into the
// same layout the kernel-side BPF program reads.
type gpuDeviceMetrics struct {
	TimestampNs uint64

	SmUtilPct  uint32
	MemUtilPct uint32

	MemTotal    uint64
	MemUsed     uint64
	MemReserved uint64

	TempC   uint32
	PowerMw uint32

	SmClockMhz  uint32
	MemClockMhz uint32

	ThrottleReasons uint64

	PcieTxKbps uint64
	PcieRxKbps uint64

	EncUtilPct uint32
	DecUtilPct uint32

	NvlinkTxKbps uint64
	NvlinkRxKbps uint64

	EccCorrectedTotal   uint64
	EccUncorrectedTotal uint64

	FanSpeedPct uint32
	ComputeMode uint32
}

// expectedEvent mirrors struct gpu_top_event in program.bpf.c. JSON
// field names follow IG's serialization, which uses the BPF struct
// field names verbatim. The mem_*_raw fields are the numeric byte
// counts; the matching mem_* (without _raw) string fields are added
// by the formatters operator and contain human-readable strings
// ("15 GB" etc.) — we don't assert on those here because they are a
// presentation concern verified separately by humans.
type expectedEvent struct {
	Device uint32 `json:"device"`

	SmUtilPct  uint32 `json:"sm_util_pct"`
	MemUtilPct uint32 `json:"mem_util_pct"`

	MemUsedRaw     uint64 `json:"mem_used_raw"`
	MemTotalRaw    uint64 `json:"mem_total_raw"`
	MemReservedRaw uint64 `json:"mem_reserved_raw"`

	TempC   uint32 `json:"temp_c"`
	PowerMw uint32 `json:"power_mw"`

	SmClockMhz  uint32 `json:"sm_clock_mhz"`
	MemClockMhz uint32 `json:"mem_clock_mhz"`

	EncUtilPct uint32 `json:"enc_util_pct"`
	DecUtilPct uint32 `json:"dec_util_pct"`

	ThrottleReasons uint64 `json:"throttle_reasons"`

	PcieTxKbps uint64 `json:"pcie_tx_kbps"`
	PcieRxKbps uint64 `json:"pcie_rx_kbps"`

	NvlinkTxKbps uint64 `json:"nvlink_tx_kbps"`
	NvlinkRxKbps uint64 `json:"nvlink_rx_kbps"`

	EccCorrectedTotal   uint64 `json:"ecc_corrected_total"`
	EccUncorrectedTotal uint64 `json:"ecc_uncorrected_total"`

	FanSpeedPct uint32 `json:"fan_speed_pct"`
	ComputeMode uint32 `json:"compute_mode"`

	TimestampNs uint64 `json:"timestamp_ns"`
}

func TestGpuTop(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("gpu_top integration test only supports ig local mode (mocks the gpu-ebpf-bridge via host bpffs pins)")
	}

	// Sanity: ensure mapValueSize matches the Go struct size. If this
	// fires, either the BPF struct or the Go struct drifted; both must
	// be kept in sync.
	require.Equal(t, mapValueSize, binary.Size(gpuDeviceMetrics{}),
		"struct gpu_device_metrics size mismatch; update mapValueSize or struct")

	// Step 1: pre-create and pin the gpu_device map externally, mocking
	// what the gpu-ebpf-bridge daemon does at startup.
	spec := &ebpf.MapSpec{
		Name:       pinnedMapName,
		Type:       ebpf.Array,
		KeySize:    mapKeySize,
		ValueSize:  mapValueSize,
		MaxEntries: mapMaxEntries,
		Pinning:    ebpf.PinByName,
	}
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: pinDir})
	require.NoError(t, err, "create and pin gpu_device map")
	t.Cleanup(func() {
		_ = m.Close()
		_ = os.Remove(filepath.Join(pinDir, pinnedMapName))
	})

	// Step 2: populate two device slots with realistic NVIDIA A100-class
	// telemetry. Devices 2..15 stay zeroed; the gadget must skip them
	// because their timestamp_ns is zero.
	dev0 := gpuDeviceMetrics{
		TimestampNs:         1_000_000_000,
		SmUtilPct:           71,
		MemUtilPct:          53,
		MemTotal:            85_899_345_920, // 80 GiB
		MemUsed:             16_106_127_360, // 15 GiB
		MemReserved:         536_870_912,    // 512 MiB
		TempC:               42,
		PowerMw:             215_000,
		SmClockMhz:          1410,
		MemClockMhz:         1593,
		EncUtilPct:          0,
		DecUtilPct:          0,
		ThrottleReasons:     0x0,
		PcieTxKbps:          12_500_000,
		PcieRxKbps:          8_750_000,
		NvlinkTxKbps:        0, // PCIe-only test SKU
		NvlinkRxKbps:        0,
		EccCorrectedTotal:   3,
		EccUncorrectedTotal: 0,
		FanSpeedPct:         0, // datacentre GPU, no controllable fan
		ComputeMode:         0, // NVML_COMPUTEMODE_DEFAULT
	}
	dev1 := gpuDeviceMetrics{
		TimestampNs:         2_000_000_000,
		SmUtilPct:           91,
		MemUtilPct:          43,
		MemTotal:            85_899_345_920,
		MemUsed:             32_212_254_720, // 30 GiB
		MemReserved:         536_870_912,
		TempC:               58,
		PowerMw:             310_000,
		SmClockMhz:          1410,
		MemClockMhz:         1593,
		EncUtilPct:          0,
		DecUtilPct:          0,
		ThrottleReasons:     0x0,
		PcieTxKbps:          9_300_000,
		PcieRxKbps:          11_400_000,
		NvlinkTxKbps:        0,
		NvlinkRxKbps:        0,
		EccCorrectedTotal:   1,
		EccUncorrectedTotal: 0,
		FanSpeedPct:         0,
		ComputeMode:         0,
	}

	require.NoError(t, m.Update(uint32(0), &dev0, ebpf.UpdateAny), "write dev0")
	require.NoError(t, m.Update(uint32(1), &dev1, ebpf.UpdateAny), "write dev1")

	// Step 3: run the gadget and validate the iter datasource output.
	// Only the two written slots must appear; the 14 zeroed slots are
	// filtered out by the BPF program's timestamp_ns == 0 check.
	expected := []*expectedEvent{
		{
			Device:            0,
			SmUtilPct:         71,
			MemUtilPct:        53,
			MemUsedRaw:        16_106_127_360,
			MemTotalRaw:       85_899_345_920,
			MemReservedRaw:    536_870_912,
			TempC:             42,
			PowerMw:           215_000,
			SmClockMhz:        1410,
			MemClockMhz:       1593,
			PcieTxKbps:        12_500_000,
			PcieRxKbps:        8_750_000,
			EccCorrectedTotal: 3,
			TimestampNs:       1_000_000_000,
		},
		{
			Device:            1,
			SmUtilPct:         91,
			MemUtilPct:        43,
			MemUsedRaw:        32_212_254_720,
			MemTotalRaw:       85_899_345_920,
			MemReservedRaw:    536_870_912,
			TempC:             58,
			PowerMw:           310_000,
			SmClockMhz:        1410,
			MemClockMhz:       1593,
			PcieTxKbps:        9_300_000,
			PcieRxKbps:        11_400_000,
			EccCorrectedTotal: 1,
			TimestampNs:       2_000_000_000,
		},
	}

	// gadget.yaml defaults to fetch-interval=1s + fetch-count=0
	// (unlimited refreshes, top-like behaviour), so the JSON output
	// is a stream of arrays — one per refresh tick. Each array
	// independently contains the same two devices, so it's enough
	// to assert that the expected entries are present in at least
	// one of the arrays.
	runnerOpts := []igrunner.Option{
		igrunner.WithFlags("--timeout=2"),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			match.MatchEntries(t, match.JSONMultiArrayMode, output, nil, expected...)
		}),
	}

	cmd := igrunner.New("gpu_top", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t)

	// Step 4: verify iteration was non-destructive. Both populated
	// entries must still hold their original values; the 14 zeroed
	// slots must still read as zero. This is the key property
	// distinguishing iter/bpf_map_elem from GADGET_MAPITER (which
	// uses BPF_MAP_LOOKUP_AND_DELETE_BATCH and drains the map).
	var got gpuDeviceMetrics
	require.NoError(t, m.Lookup(uint32(0), &got), "dev0 still present")
	require.Equal(t, dev0, got, "dev0 unchanged after iteration")
	require.NoError(t, m.Lookup(uint32(1), &got), "dev1 still present")
	require.Equal(t, dev1, got, "dev1 unchanged after iteration")

	var zero gpuDeviceMetrics
	for k := uint32(2); k < mapMaxEntries; k++ {
		require.NoError(t, m.Lookup(k, &got), "slot %d still readable", k)
		require.Equal(t, zero, got, "slot %d still zeroed after iteration", k)
	}
}

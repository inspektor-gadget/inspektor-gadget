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

// Package nvml abstracts the NVIDIA Management Library so the bridge's
// poller loop can be exercised against either real hardware
// (backend=real, requires cgo + libnvidia-ml.so.1 + NVIDIA driver) or
// fabricated data (backend=mock, runs anywhere).
//
// The interface intentionally exposes only the data shapes the bridge
// needs to populate its BPF maps, not the full NVML surface. Adding a
// new field to the bridge's maps generally means adding one method here
// and implementing it in both backends.
package nvml

import (
	"context"
	"errors"
)

// ErrNotAvailable indicates the underlying library could not be loaded
// (typically because libnvidia-ml.so.1 is missing or the NVIDIA driver
// is not loaded on this host). The bridge treats this as a non-fatal
// "no GPU on this node" condition.
var ErrNotAvailable = errors.New("nvml: library or driver not available")

// Poller is the single abstraction the bridge needs over NVML. Init is
// called once at startup; Devices() returns the per-device snapshot
// (everything the gpu_device map needs); ProcessSamples() returns the
// per-PID rolling-window samples since lastSeenNs (everything the
// gpu_per_pid_* maps need).
//
// Methods are expected to return ErrNotAvailable on permanent
// unavailability and a more specific error on transient failures.
// Implementations should be safe for sequential use; the poller calls
// them from a single goroutine so internal locking is not required.
type Poller interface {
	// Init enumerates devices and prepares the backend for sampling.
	// Must be called before any other method. Idempotent.
	Init(ctx context.Context) error

	// Devices returns the current per-device snapshot, one entry per
	// physical GPU (or MIG compute instance once MIG support lands).
	// The returned slice is owned by the caller.
	Devices(ctx context.Context) ([]DeviceSnapshot, error)

	// ProcessSamples returns per-(pid, device) utilization samples
	// produced since lastSeenNs. Implementations should advance their
	// internal "last seen" timestamp atomically with the returned
	// slice so callers can pass back the largest timestamp they saw
	// on the next call. lastSeenNs == 0 means "give me whatever you
	// have".
	ProcessSamples(ctx context.Context, lastSeenNs uint64) ([]ProcessSample, error)

	// Close releases any backend resources. Idempotent.
	Close() error
}

// DeviceSnapshot is the per-device data the bridge needs to fill
// gpu_device_metrics. Fields the underlying source cannot provide
// should be left as zero.
type DeviceSnapshot struct {
	Index uint32 // 0-based device index
	UUID  string // optional, useful for logs only
	Name  string // human-readable device name (e.g. "NVIDIA A100-SXM4-80GB")

	TimestampNs uint64

	SmUtilPct  uint32 // 0-100
	MemUtilPct uint32 // 0-100

	MemTotal    uint64 // bytes
	MemUsed     uint64
	MemReserved uint64 // driver overhead

	TempC   uint32
	PowerMw uint32 // milliwatts

	SmClockMhz  uint32
	MemClockMhz uint32

	ThrottleReasons uint64 // NVML clocksEventReasons bitmask

	PcieTxKbps uint64
	PcieRxKbps uint64

	EncUtilPct uint32
	DecUtilPct uint32

	NvlinkTxKbps uint64 // 0 on non-NVLink GPUs
	NvlinkRxKbps uint64

	EccCorrectedTotal   uint64
	EccUncorrectedTotal uint64

	FanSpeedPct uint32 // 0 if no controllable fan
	ComputeMode uint32 // NVML_COMPUTEMODE_* enum value
}

// ProcessSample is one per-(pid, device) utilization measurement. The
// real backend builds these from nvmlDeviceGetProcessUtilization (which
// returns SM/mem/enc/dec util) supplemented by
// nvmlDeviceGetComputeRunningProcesses (for the used_gpu_memory of PIDs
// that aren't actively executing compute).
type ProcessSample struct {
	Pid         uint32
	DeviceIndex uint32
	TimestampNs uint64

	UsedGpuMemory uint64 // bytes
	SmUtilPct     uint32
	MemUtilPct    uint32
	EncUtilPct    uint32
	DecUtilPct    uint32

	MigInstance uint8 // 0 in v1
}

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

package maps

// Public Go struct types mirroring the BPF struct definitions in
// include/gadget/gpu_types.h. The bpf2go-generated types in
// gputypes_*_bpfel.go are package-private; this file re-exports them
// as Meta/DeviceMetrics/PidMetrics/PidMetricsAggregated so consumers
// of the maps package have a stable, capitalized API surface that
// doesn't change when bpf2go is re-run.
//
// The Update* methods in maps.go take pointers to these types and
// cast to the bpf2go types internally. The casts are safe because both
// pairs are declared from the exact same BPF struct layout (bpf2go
// reads the BPF object's BTF; we re-declare with matching field order
// and types).

// Meta mirrors struct gpu_meta in include/gadget/gpu_types.h.
type Meta = gputypesGpuMeta

// DeviceMetrics mirrors struct gpu_device_metrics in
// include/gadget/gpu_types.h.
type DeviceMetrics = gputypesGpuDeviceMetrics

// PidMetrics mirrors struct gpu_pid_metrics in
// include/gadget/gpu_types.h (detailed per-(pid, device) record).
type PidMetrics = gputypesGpuPidMetrics

// PidMetricsAggregated mirrors struct gpu_pid_metrics_aggregated in
// include/gadget/gpu_types.h (convenience per-pid aggregated record).
type PidMetricsAggregated = gputypesGpuPidMetricsAggregated

// SchemaVersion is the version the bridge writes into Meta.SchemaVersion.
// Matches GPU_SCHEMA_VERSION in include/gadget/gpu_types.h.
const SchemaVersion uint32 = 1

// MaxDevices matches GPU_MAX_DEVICES in include/gadget/gpu_types.h.
// The gpu_device ARRAY has this many slots.
const MaxDevices = 16

// DevicePrimaryMulti is the sentinel value written into
// PidMetricsAggregated.GpuDevicePrimary when a single PID holds contexts
// on more than one device. Matches GPU_DEVICE_PRIMARY_MULTI in
// include/gadget/gpu_types.h.
const DevicePrimaryMulti uint8 = 0xFF

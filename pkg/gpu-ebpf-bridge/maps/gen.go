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

// Package maps owns the four bpffs-pinned BPF maps that gpu-ebpf-bridge
// publishes as its API contract:
//
//	/sys/fs/bpf/gpu_meta
//	/sys/fs/bpf/gpu_device
//	/sys/fs/bpf/gpu_per_pid
//	/sys/fs/bpf/gpu_per_pid_per_device
//
// The bridge loads the small BPF object bpf/gpu_types.bpf.c (compiled
// by bpf2go and embedded at compile time) so the four maps come into
// the kernel with proper BTF for struct gpu_meta, gpu_device_metrics,
// gpu_pid_metrics, and gpu_pid_metrics_aggregated. Consumers can then
// CO-RE-read those maps by field name.
package maps

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} gputypes ./bpf/gpu_types.bpf.c -- -I./bpf/

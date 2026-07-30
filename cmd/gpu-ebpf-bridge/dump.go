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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/maps"
)

// runDump implements --dump: open each bpffs-pinned bridge map
// read-only, iterate it, and print its contents. Bridge does not need
// to be running. Useful when bpftool is not installed.
func runDump(pinDir string) error {
	if err := dumpMeta(filepath.Join(pinDir, maps.MapNameMeta)); err != nil {
		return err
	}
	if err := dumpDevice(filepath.Join(pinDir, maps.MapNameDevice)); err != nil {
		return err
	}
	if err := dumpPerPid(filepath.Join(pinDir, maps.MapNamePerPid)); err != nil {
		return err
	}
	return dumpPerPidPerDevice(filepath.Join(pinDir, maps.MapNamePerPidPerDevice))
}

func dumpMeta(path string) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer m.Close()
	var v maps.Meta
	key := uint32(0)
	if err := m.Lookup(&key, &v); err != nil {
		return fmt.Errorf("lookup %s: %w", path, err)
	}
	fmt.Fprintln(os.Stdout, "# gpu_meta")
	fmt.Fprintf(os.Stdout, "  %+v\n\n", v)
	return nil
}

func dumpDevice(path string) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer m.Close()
	fmt.Fprintln(os.Stdout, "# gpu_device")
	var (
		key uint32
		val maps.DeviceMetrics
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.TimestampNs == 0 {
			// ARRAY slots are zero-initialised; skip unwritten entries.
			continue
		}
		fmt.Fprintf(os.Stdout, "  [device %d] %+v\n", key, val)
	}
	fmt.Fprintln(os.Stdout)
	return iter.Err()
}

func dumpPerPid(path string) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer m.Close()
	fmt.Fprintln(os.Stdout, "# gpu_per_pid")
	type entry struct {
		pid uint32
		val maps.PidMetricsAggregated
	}
	var (
		entries []entry
		key     uint32
		val     maps.PidMetricsAggregated
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		entries = append(entries, entry{pid: key, val: val})
	}
	if err := iter.Err(); err != nil {
		return err
	}
	// LRU_HASH iteration order is not deterministic; sort by PID so the
	// dump is stable across runs.
	sort.Slice(entries, func(i, j int) bool { return entries[i].pid < entries[j].pid })
	for _, e := range entries {
		fmt.Fprintf(os.Stdout, "  [pid %d] %+v\n", e.pid, e.val)
	}
	fmt.Fprintln(os.Stdout)
	return nil
}

func dumpPerPidPerDevice(path string) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer m.Close()
	fmt.Fprintln(os.Stdout, "# gpu_per_pid_per_device")
	type entry struct {
		key uint64
		val maps.PidMetrics
	}
	var (
		entries []entry
		key     uint64
		val     maps.PidMetrics
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		entries = append(entries, entry{key: key, val: val})
	}
	if err := iter.Err(); err != nil {
		return err
	}
	// LRU_HASH iteration order is not deterministic; sort by composite
	// key so the dump is stable across runs.
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	for _, e := range entries {
		pid, dev := maps.SplitPerPidPerDeviceKey(e.key)
		fmt.Fprintf(os.Stdout, "  [pid %d dev %d] %+v\n", pid, dev, e.val)
	}
	fmt.Fprintln(os.Stdout)
	return nil
}

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

// Package poller drives the main bridge loop: every PollInterval, ask
// the nvml.Poller for the current device snapshot + per-PID samples
// and write the results into the bpffs-pinned BPF maps. It also
// maintains the gpu_meta freshness signal that consumers rely on.
package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/maps"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/nvml"
)

// Config selects the poll cadence and the upstream NVML backend.
type Config struct {
	// PollInterval is the time between Poller.Devices() /
	// ProcessSamples() ticks. Defaults to 100 ms (10 Hz).
	PollInterval time.Duration

	// Source is the upstream telemetry provider (mock or real NVML).
	Source nvml.Poller

	// Bridge is the bpffs-pinned-map writer. Owned by the caller;
	// the poller will Update*() it but never Close/Unpin it.
	Bridge *maps.Bridge

	// Logger is used for warnings and per-tick info logs. Defaults to
	// slog.Default() if nil.
	Logger *slog.Logger
}

// Poller is the main bridge loop.
type Poller struct {
	cfg    Config
	logger *slog.Logger
	helper uint32 // os.Getpid() captured once

	mu sync.Mutex
	// lastSeenPerDevice tracks the highest sample timestamp returned
	// by Source.ProcessSamples for each device, so the next call can
	// ask only for samples newer than that.
	lastSeenPerDevice map[uint32]uint64

	// The following are touched only from tick(), which Run() calls
	// serially, so they need no locking.

	// prevPids / prevPidDevKeys are the aggregated PIDs and composite
	// (pid<<32|dev) keys written on the previous tick, used to detect
	// and delete departed entries.
	prevPids       map[uint32]struct{}
	prevPidDevKeys map[uint64]struct{}
}

// New constructs a Poller with sensible defaults applied.
func New(cfg Config) (*Poller, error) {
	if cfg.Source == nil {
		return nil, errors.New("poller: Config.Source is required")
	}
	if cfg.Bridge == nil {
		return nil, errors.New("poller: Config.Bridge is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Poller{
		cfg:               cfg,
		logger:            cfg.Logger,
		helper:            uint32(os.Getpid()),
		lastSeenPerDevice: make(map[uint32]uint64),
		prevPids:          make(map[uint32]struct{}),
		prevPidDevKeys:    make(map[uint64]struct{}),
	}, nil
}

// Run drives the poll loop until ctx is cancelled. It returns nil on
// clean shutdown and the wrapped Init/loop error otherwise.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.cfg.Source.Init(ctx); err != nil {
		return fmt.Errorf("nvml init: %w", err)
	}
	defer func() { _ = p.cfg.Source.Close() }()

	// Tick once immediately so consumers see fresh data within
	// ~PollInterval of bridge startup, then on every PollInterval.
	if err := p.tick(ctx); err != nil {
		p.logger.Warn("initial tick failed", "err", err)
	}

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.tick(ctx); err != nil {
				// Transient errors don't abort the loop; the bridge is
				// expected to be best-effort. The gpu_meta freshness
				// signal is what consumers should rely on.
				p.logger.Warn("tick failed", "err", err)
			}
		}
	}
}

func (p *Poller) tick(ctx context.Context) error {
	devs, devErr := p.cfg.Source.Devices(ctx)
	if devErr != nil {
		return fmt.Errorf("devices: %w", devErr)
	}

	// Write each device's metrics.
	for _, d := range devs {
		mapVal := deviceSnapshotToMap(d)
		if err := p.cfg.Bridge.UpdateDevice(d.Index, &mapVal); err != nil {
			p.logger.Warn("UpdateDevice failed", "idx", d.Index, "err", err)
		}
	}

	// Per-PID samples. Use the minimum lastSeen across devices to avoid
	// missing samples for newly-appearing devices; the real backend
	// keys its rolling window per device.
	lastSeen := p.minLastSeen()
	samples, sampErr := p.cfg.Source.ProcessSamples(ctx, lastSeen)
	if sampErr != nil {
		p.logger.Warn("ProcessSamples failed", "err", sampErr)
	}

	// NVML's nvmlDeviceGetProcessUtilization returns a rolling window
	// of samples per device, and within one tick the same (pid, dev)
	// tuple typically appears multiple times with varying utilization
	// values. Aggregate same-key samples within the tick before
	// writing to gpu_per_pid_per_device, taking the max over the
	// utilization fields so consumers see the busiest moment in the
	// window (last-write-wins would arbitrarily drop the peaks).
	type pidDevKey struct {
		Pid uint32
		Dev uint32
	}
	type perDevAgg struct {
		ts      uint64
		usedMem uint64
		smMax   uint32
		memMax  uint32
		encMax  uint32
		decMax  uint32
		migInst uint8
	}
	perDev := make(map[pidDevKey]*perDevAgg)

	// Advance per-device watermark from every observed sample, even
	// for PIDs we filter out below.
	for _, s := range samples {
		p.advanceLastSeen(s.DeviceIndex, s.TimestampNs)
	}

	for _, s := range samples {
		// Skip NVML's "unattributed/system" bucket. Pid 0 entries are
		// driver/kernel-side activity that NVML cannot ascribe to a
		// userspace process; emitting them into gpu_per_pid would let
		// consumers wrongly enrich kernel-init-side eBPF events with
		// nonsensical GPU stats. See nvmlProcessUtilizationSample_t
		// in <nvml.h>.
		if s.Pid == 0 {
			continue
		}

		key := pidDevKey{Pid: s.Pid, Dev: s.DeviceIndex}
		a := perDev[key]
		if a == nil {
			a = &perDevAgg{
				ts:      s.TimestampNs,
				usedMem: s.UsedGpuMemory,
				migInst: s.MigInstance,
			}
			perDev[key] = a
		}
		// UsedGpuMemory is a steady-state value (set once per tick by
		// GetComputeRunningProcesses in the real backend); take any
		// non-zero seen so memory-only fallback entries don't clobber
		// utilization entries that happen to have UsedGpuMemory==0.
		if s.UsedGpuMemory > a.usedMem {
			a.usedMem = s.UsedGpuMemory
		}
		if s.SmUtilPct > a.smMax {
			a.smMax = s.SmUtilPct
		}
		if s.MemUtilPct > a.memMax {
			a.memMax = s.MemUtilPct
		}
		if s.EncUtilPct > a.encMax {
			a.encMax = s.EncUtilPct
		}
		if s.DecUtilPct > a.decMax {
			a.decMax = s.DecUtilPct
		}
		if s.TimestampNs > a.ts {
			a.ts = s.TimestampNs
		}
	}

	// Group per-(pid, dev) aggregates by PID, collecting batch upserts.
	type aggBuilder struct {
		ts        uint64
		usedTotal uint64
		smMax     uint32
		memMax    uint32
		firstDev  uint8
		devSet    map[uint8]struct{}
	}
	agg := make(map[uint32]*aggBuilder)

	pdKeys := make([]uint64, 0, len(perDev))
	pdVals := make([]maps.PidMetrics, 0, len(perDev))
	curPidDevKeys := make(map[uint64]struct{}, len(perDev))

	for key, a := range perDev {
		// Detailed per-(pid, dev) entry, written once per unique key
		// per tick (no more last-write-wins).
		detail := maps.PidMetrics{
			TimestampNs:   a.ts,
			UsedGpuMemory: a.usedMem,
			SmUtilPct:     a.smMax,
			MemUtilPct:    a.memMax,
			EncUtilPct:    a.encMax,
			DecUtilPct:    a.decMax,
			GpuDevice:     uint8(key.Dev),
			MigInstance:   a.migInst,
		}
		k := maps.PerPidPerDeviceKey(key.Pid, key.Dev)
		pdKeys = append(pdKeys, k)
		pdVals = append(pdVals, detail)
		curPidDevKeys[k] = struct{}{}

		// Aggregated builder for this PID.
		b := agg[key.Pid]
		if b == nil {
			b = &aggBuilder{
				ts:       a.ts,
				firstDev: uint8(key.Dev),
				devSet:   make(map[uint8]struct{}),
			}
			agg[key.Pid] = b
		}
		b.usedTotal += a.usedMem
		if a.smMax > b.smMax {
			b.smMax = a.smMax
		}
		if a.memMax > b.memMax {
			b.memMax = a.memMax
		}
		b.devSet[uint8(key.Dev)] = struct{}{}
		if a.ts > b.ts {
			b.ts = a.ts
		}
	}

	pidKeys := make([]uint32, 0, len(agg))
	pidVals := make([]maps.PidMetricsAggregated, 0, len(agg))
	curPids := make(map[uint32]struct{}, len(agg))

	for pid, b := range agg {
		// DeviceCount = number of distinct devices the PID was seen
		// on (was: number of samples, which exploded for noisy PIDs).
		devCount := uint8(len(b.devSet))
		if devCount == 0 {
			devCount = 1
		}

		mapVal := maps.PidMetricsAggregated{
			TimestampNs:        b.ts,
			UsedGpuMemoryTotal: b.usedTotal,
			SmUtilPctMax:       b.smMax,
			MemUtilPctMax:      b.memMax,
			GpuDevicePrimary:   b.firstDev,
			DeviceCount:        devCount,
		}
		if devCount > 1 {
			mapVal.GpuDevicePrimary = maps.DevicePrimaryMulti
		}
		pidKeys = append(pidKeys, pid)
		pidVals = append(pidVals, mapVal)
		curPids[pid] = struct{}{}
	}

	// Write all upserts first (one batched syscall per map), then delete
	// departed entries, then bump gpu_meta last — so a consumer reading
	// mid-tick never sees a half-updated snapshot of a live PID and only
	// sees the freshness bump after both upserts and deletions land.
	if _, err := p.cfg.Bridge.BatchUpdatePerPidPerDevice(pdKeys, pdVals); err != nil {
		p.logger.Warn("BatchUpdatePerPidPerDevice failed", "n", len(pdKeys), "err", err)
	}
	if _, err := p.cfg.Bridge.BatchUpdatePerPid(pidKeys, pidVals); err != nil {
		p.logger.Warn("BatchUpdatePerPid failed", "n", len(pidKeys), "err", err)
	}

	// Delete entries present last tick but gone now, so dead processes
	// don't linger with stale metrics (and can't trigger false
	// GPU-starvation events for a reused PID).
	var delPidDev []uint64
	for k := range p.prevPidDevKeys {
		if _, ok := curPidDevKeys[k]; !ok {
			delPidDev = append(delPidDev, k)
		}
	}
	if _, err := p.cfg.Bridge.BatchDeletePerPidPerDevice(delPidDev); err != nil {
		p.logger.Warn("BatchDeletePerPidPerDevice failed", "n", len(delPidDev), "err", err)
	}
	var delPids []uint32
	for pid := range p.prevPids {
		if _, ok := curPids[pid]; !ok {
			delPids = append(delPids, pid)
		}
	}
	if _, err := p.cfg.Bridge.BatchDeletePerPid(delPids); err != nil {
		p.logger.Warn("BatchDeletePerPid failed", "n", len(delPids), "err", err)
	}
	p.prevPidDevKeys = curPidDevKeys
	p.prevPids = curPids

	// gpu_meta last, so consumers that gate enrichment on
	// last_update_boottime_ns see the per-PID data first.
	var bt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt); err != nil {
		return fmt.Errorf("clock_gettime(CLOCK_BOOTTIME): %w", err)
	}
	meta := maps.Meta{
		SchemaVersion:        maps.SchemaVersion,
		N_devices:            uint32(len(devs)),
		LastUpdateBoottimeNs: uint64(bt.Nano()),
		HelperPid:            p.helper,
		ClockOffsetNs:        computeClockOffset(),
	}
	if err := p.cfg.Bridge.UpdateMeta(&meta); err != nil {
		// Meta is essential for consumer freshness checks; this should
		// be loud.
		return fmt.Errorf("UpdateMeta: %w", err)
	}

	return nil
}

func (p *Poller) minLastSeen() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lastSeenPerDevice) == 0 {
		return 0
	}
	var min uint64
	first := true
	for _, ts := range p.lastSeenPerDevice {
		if first || ts < min {
			min = ts
			first = false
		}
	}
	return min
}

func (p *Poller) advanceLastSeen(dev uint32, ts uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ts > p.lastSeenPerDevice[dev] {
		p.lastSeenPerDevice[dev] = ts
	}
}

// computeClockOffset returns (CLOCK_REALTIME - CLOCK_BOOTTIME) in nanoseconds
// as a signed int64. Consumers convert an NVML wall-clock (CLOCK_REALTIME)
// timestamp to CLOCK_BOOTTIME via: boottime = realtime - offset.
//
// It brackets a single CLOCK_BOOTTIME read between two CLOCK_REALTIME reads
// and retries until the bracket is tight (< 100 µs), so a preemption or
// SIGSTOP between the syscalls can't skew the offset. Running it every tick
// means NTP step adjustments are picked up within one poll interval.
//
// NOTE: this uses golang.org/x/sys/unix; the stdlib syscall package does not
// define CLOCK_BOOTTIME / CLOCK_REALTIME on Linux.
func computeClockOffset() int64 {
	for {
		var r1, b, r2 unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_REALTIME, &r1); err != nil {
			return 0
		}
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &b); err != nil {
			return 0
		}
		if err := unix.ClockGettime(unix.CLOCK_REALTIME, &r2); err != nil {
			return 0
		}
		if r2.Nano()-r1.Nano() < 100_000 { // < 100 µs → clean bracket
			return (r1.Nano()+r2.Nano())/2 - b.Nano()
		}
		// Preempted or SIGSTOP'd between the reads — retry.
	}
}

func deviceSnapshotToMap(d nvml.DeviceSnapshot) maps.DeviceMetrics {
	return maps.DeviceMetrics{
		TimestampNs:         d.TimestampNs,
		SmUtilPct:           d.SmUtilPct,
		MemUtilPct:          d.MemUtilPct,
		MemTotal:            d.MemTotal,
		MemUsed:             d.MemUsed,
		MemReserved:         d.MemReserved,
		TempC:               d.TempC,
		PowerMw:             d.PowerMw,
		SmClockMhz:          d.SmClockMhz,
		MemClockMhz:         d.MemClockMhz,
		ThrottleReasons:     d.ThrottleReasons,
		PcieTxKbps:          d.PcieTxKbps,
		PcieRxKbps:          d.PcieRxKbps,
		EncUtilPct:          d.EncUtilPct,
		DecUtilPct:          d.DecUtilPct,
		NvlinkTxKbps:        d.NvlinkTxKbps,
		NvlinkRxKbps:        d.NvlinkRxKbps,
		EccCorrectedTotal:   d.EccCorrectedTotal,
		EccUncorrectedTotal: d.EccUncorrectedTotal,
		FanSpeedPct:         d.FanSpeedPct,
		ComputeMode:         d.ComputeMode,
	}
}

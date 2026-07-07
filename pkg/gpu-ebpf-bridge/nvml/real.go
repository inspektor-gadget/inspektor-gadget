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

//go:build cgo && nvml

// Real NVML Poller. Compiled in only when CGO is enabled and the
// 'nvml' build tag is set, because go-nvml ultimately dlopen()s
// libnvidia-ml.so.1 via cgo and would otherwise force CGO on the
// whole tree.
//
// Build:    CGO_ENABLED=1 go build -tags nvml ./cmd/gpu-ebpf-bridge
// Run:      ./gpu-ebpf-bridge --mode=real
//
// All NVML calls are wrapped in safe(), which tolerates:
//
//   - ERROR_NOT_SUPPORTED (older GPUs lack some fields), reported as 0
//   - ERROR_NOT_FOUND     (PID exited mid-query),         reported as 0
//   - ERROR_LIBRARY_NOT_FOUND / ERROR_DRIVER_NOT_LOADED   propagated
//     as nvml.ErrNotAvailable for the bridge's auto-mode fallback.
//
// Other errors are returned to the poller, which logs them and skips
// the affected sample.

package nvml

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	xnvml "github.com/NVIDIA/go-nvml/pkg/nvml"
)

// Real is the production NVML-backed Poller.
type Real struct {
	mu          sync.Mutex
	handles     []xnvml.Device
	lastSeenTs  map[uint32]uint64 // per device, for DeviceGetProcessUtilization rolling window
	logger      *slog.Logger
	libraryPath string // optional absolute path to libnvidia-ml.so.1; empty = default dlopen
	initialized bool   // true between a successful Init() and Close()
	closed      bool
}

// NewReal constructs a real-NVML Poller. Init() must still be called
// before sampling.
func NewReal(logger *slog.Logger) *Real {
	if logger == nil {
		logger = slog.Default()
	}
	return &Real{
		logger:     logger,
		lastSeenTs: make(map[uint32]uint64),
	}
}

// SetLibraryPath tells the Real poller to dlopen libnvidia-ml.so.1
// from the given absolute path instead of relying on the dynamic
// linker's default search. Must be called before Init(). Empty path
// (default) leaves the search to LD_LIBRARY_PATH / ld.so.cache.
//
// Motivation: pointing at an absolute libnvidia-ml.so.1 lets the
// bridge, when running as a container that bind-mounts the host's
// /usr, load the host's NVIDIA driver without also polluting the
// linker search path with the host's libc / libpthread / etc.
// (which would cause glibc's stack canaries to mismatch across
// distro versions and trigger a "stack smashing detected" abort).
func (r *Real) SetLibraryPath(p string) {
	r.libraryPath = p
}

// safeRet converts an xnvml.Return into a Go error, translating the
// "no library / no driver" returns into our ErrNotAvailable so the
// bridge can do its auto-mode fallback. ERROR_NOT_SUPPORTED and
// ERROR_NOT_FOUND are treated as soft errors (caller should ignore
// the value).
type softErr struct{ Return xnvml.Return }

func (e softErr) Error() string { return xnvml.ErrorString(e.Return) }

func wrap(ret xnvml.Return) error {
	switch ret {
	case xnvml.SUCCESS:
		return nil
	case xnvml.ERROR_NOT_SUPPORTED, xnvml.ERROR_NOT_FOUND:
		return softErr{ret}
	case xnvml.ERROR_LIBRARY_NOT_FOUND, xnvml.ERROR_DRIVER_NOT_LOADED:
		return fmt.Errorf("%w: %s", ErrNotAvailable, xnvml.ErrorString(ret))
	default:
		return fmt.Errorf("nvml: %s", xnvml.ErrorString(ret))
	}
}

func isSoft(err error) bool {
	var s softErr
	return errors.As(err, &s)
}

func (r *Real) Init(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Idempotent: the docstring on nvml.Poller.Init and callers (main
	// binary + poller.Run) both invoke Init, so we must tolerate a
	// second call. Returning early here also avoids re-calling
	// SetLibraryOptions on go-nvml, which fails with "library already
	// loaded" once refcount > 0 (see go-nvml pkg/nvml/api.go).
	if r.initialized {
		return nil
	}

	if r.libraryPath != "" {
		if err := xnvml.SetLibraryOptions(xnvml.WithLibraryPath(r.libraryPath)); err != nil {
			return fmt.Errorf("setting NVML library path %q: %w", r.libraryPath, err)
		}
	}
	if err := wrap(xnvml.Init()); err != nil {
		return err
	}
	// From this point on the library is loaded; we must call Shutdown
	// at Close() time to balance Init.
	r.initialized = true
	count, ret := xnvml.DeviceGetCount()
	if err := wrap(ret); err != nil {
		_ = xnvml.Shutdown()
		r.initialized = false
		return fmt.Errorf("DeviceGetCount: %w", err)
	}
	r.handles = make([]xnvml.Device, 0, count)
	for i := 0; i < count; i++ {
		d, ret := xnvml.DeviceGetHandleByIndex(i)
		if err := wrap(ret); err != nil {
			_ = xnvml.Shutdown()
			r.initialized = false
			return fmt.Errorf("DeviceGetHandleByIndex(%d): %w", i, err)
		}
		r.handles = append(r.handles, d)
	}
	r.logger.Info("real NVML backend initialised", "devices", len(r.handles))
	return nil
}

func (r *Real) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.handles = nil
	if !r.initialized {
		// Init never succeeded, so the underlying library was never
		// loaded into this process. Calling xnvml.Shutdown() would
		// trip an unresolved-symbol error in the C side.
		return nil
	}
	r.initialized = false
	return wrap(xnvml.Shutdown())
}

func (r *Real) Devices(_ context.Context) ([]DeviceSnapshot, error) {
	r.mu.Lock()
	handles := append([]xnvml.Device(nil), r.handles...)
	r.mu.Unlock()

	tsNs := uint64(time.Now().UnixNano())
	out := make([]DeviceSnapshot, 0, len(handles))

	for i, dev := range handles {
		idx := uint32(i)
		snap := DeviceSnapshot{Index: idx, TimestampNs: tsNs}

		if uuid, ret := dev.GetUUID(); wrap(ret) == nil {
			snap.UUID = uuid
		}
		if name, ret := dev.GetName(); wrap(ret) == nil {
			snap.Name = name
		}

		if u, ret := dev.GetUtilizationRates(); wrap(ret) == nil {
			snap.SmUtilPct = u.Gpu
			snap.MemUtilPct = u.Memory
		} else if !isSoft(wrap(ret)) {
			r.logger.Debug("GetUtilizationRates", "dev", idx, "err", wrap(ret))
		}

		if m, ret := dev.GetMemoryInfo_v2(); wrap(ret) == nil {
			snap.MemTotal = m.Total
			snap.MemUsed = m.Used
			snap.MemReserved = m.Reserved
		} else if m2, ret2 := dev.GetMemoryInfo(); wrap(ret2) == nil {
			snap.MemTotal = m2.Total
			snap.MemUsed = m2.Used
		}

		if t, ret := dev.GetTemperature(xnvml.TEMPERATURE_GPU); wrap(ret) == nil {
			snap.TempC = t
		}
		if p, ret := dev.GetPowerUsage(); wrap(ret) == nil {
			snap.PowerMw = p
		}
		if c, ret := dev.GetClockInfo(xnvml.CLOCK_SM); wrap(ret) == nil {
			snap.SmClockMhz = c
		}
		if c, ret := dev.GetClockInfo(xnvml.CLOCK_MEM); wrap(ret) == nil {
			snap.MemClockMhz = c
		}
		if reasons, ret := dev.GetCurrentClocksEventReasons(); wrap(ret) == nil {
			snap.ThrottleReasons = reasons
		} else if reasons, ret := dev.GetCurrentClocksThrottleReasons(); wrap(ret) == nil {
			snap.ThrottleReasons = reasons
		}
		if rx, ret := dev.GetPcieThroughput(xnvml.PCIE_UTIL_RX_BYTES); wrap(ret) == nil {
			snap.PcieRxKbps = uint64(rx)
		}
		if tx, ret := dev.GetPcieThroughput(xnvml.PCIE_UTIL_TX_BYTES); wrap(ret) == nil {
			snap.PcieTxKbps = uint64(tx)
		}
		if u, _, ret := dev.GetEncoderUtilization(); wrap(ret) == nil {
			snap.EncUtilPct = u
		}
		if u, _, ret := dev.GetDecoderUtilization(); wrap(ret) == nil {
			snap.DecUtilPct = u
		}
		if n, ret := dev.GetTotalEccErrors(xnvml.MEMORY_ERROR_TYPE_CORRECTED, xnvml.VOLATILE_ECC); wrap(ret) == nil {
			snap.EccCorrectedTotal = n
		}
		if n, ret := dev.GetTotalEccErrors(xnvml.MEMORY_ERROR_TYPE_UNCORRECTED, xnvml.VOLATILE_ECC); wrap(ret) == nil {
			snap.EccUncorrectedTotal = n
		}
		if f, ret := dev.GetFanSpeed(); wrap(ret) == nil {
			snap.FanSpeedPct = f
		}
		if cm, ret := dev.GetComputeMode(); wrap(ret) == nil {
			snap.ComputeMode = uint32(cm)
		}

		out = append(out, snap)
	}
	return out, nil
}

func (r *Real) ProcessSamples(_ context.Context, lastSeenNs uint64) ([]ProcessSample, error) {
	r.mu.Lock()
	handles := append([]xnvml.Device(nil), r.handles...)
	r.mu.Unlock()

	// Index per-PID memory usage from GetComputeRunningProcesses for
	// processes that aren't actively executing compute right now (so
	// DeviceGetProcessUtilization wouldn't return them) but still hold
	// VRAM. The merge below prefers utilization data when available.
	type pidDevKey struct {
		Pid uint32
		Dev uint32
	}
	memByPidDev := make(map[pidDevKey]uint64)

	out := make([]ProcessSample, 0, 32)

	for i, dev := range handles {
		devIdx := uint32(i)

		// Memory-only data first.
		if procs, ret := dev.GetComputeRunningProcesses(); wrap(ret) == nil {
			for _, p := range procs {
				memByPidDev[pidDevKey{Pid: p.Pid, Dev: devIdx}] = p.UsedGpuMemory
			}
		}

		// Per-PID utilization samples. Rolling window: NVML returns
		// samples newer than the lastSeenTs we pass. lastSeenTs is kept
		// in NVML's native unit (CLOCK_REALTIME microseconds), so the
		// caller's watermark — which it derives from ProcessSample.
		// TimestampNs (nanoseconds, see below) — is converted to µs
		// before comparison. advanceLastSeen only moves forward, so
		// clamping to the caller's value here is safe.
		r.mu.Lock()
		seen := r.lastSeenTs[devIdx]
		r.mu.Unlock()
		if lastSeenUs := lastSeenNs / 1000; lastSeenUs > seen {
			// Caller is willing to forget older samples (e.g. on first
			// tick or after a backend reset).
			seen = lastSeenUs
		}

		samples, ret := dev.GetProcessUtilization(seen)
		err := wrap(ret)
		if err != nil && !isSoft(err) {
			r.logger.Debug("GetProcessUtilization", "dev", devIdx, "err", err)
			continue
		}

		var maxTs uint64
		for _, s := range samples {
			if s.TimeStamp > maxTs {
				maxTs = s.TimeStamp
			}
			key := pidDevKey{Pid: s.Pid, Dev: devIdx}
			used := memByPidDev[key]
			delete(memByPidDev, key)
			out = append(out, ProcessSample{
				Pid:         s.Pid,
				DeviceIndex: devIdx,
				// s.TimeStamp is CLOCK_REALTIME microseconds since the
				// Unix epoch (verified empirically on an A100, driver
				// 580.126.09). Preserve the real sample time — not
				// time.Now() — so consumers see the true per-device
				// sample time.
				TimestampNs:   s.TimeStamp * 1000,
				UsedGpuMemory: used,
				SmUtilPct:     s.SmUtil,
				MemUtilPct:    s.MemUtil,
				EncUtilPct:    s.EncUtil,
				DecUtilPct:    s.DecUtil,
			})
		}
		if maxTs > 0 {
			r.mu.Lock()
			if maxTs > r.lastSeenTs[devIdx] {
				r.lastSeenTs[devIdx] = maxTs
			}
			r.mu.Unlock()
		}

		// Emit memory-only entries for PIDs that didn't show up in
		// utilization samples this round (idle but still holding VRAM).
		// These have no NVML sample timestamp; leave TimestampNs == 0.
		for key, used := range memByPidDev {
			if key.Dev != devIdx {
				continue
			}
			out = append(out, ProcessSample{
				Pid:           key.Pid,
				DeviceIndex:   devIdx,
				UsedGpuMemory: used,
			})
			delete(memByPidDev, key)
		}
	}
	return out, nil
}

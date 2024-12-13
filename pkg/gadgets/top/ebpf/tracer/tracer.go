// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/tklauser/numcpus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/bpfstats"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/piditer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type Config struct {
	MaxRows    int
	Interval   time.Duration
	Iterations int
	SortBy     []string
}

type programStats struct {
	runtime  int64
	runCount uint64
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataNodeEnricher
	eventCallback func(*top.Event[types.Stats])
	done          chan bool

	iter                *piditer.PidIter
	useFallbackIterator bool

	startStats map[string]programStats
	prevStats  map[string]programStats
	colMap     columns.ColumnMap[types.Stats]
}

func NewTracer(config *Config, enricher gadgets.DataNodeEnricher,
	eventCallback func(*top.Event[types.Stats]),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
		done:          make(chan bool),
		prevStats:     make(map[string]programStats),
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		t.close()
		return nil, err
	}
	t.colMap = statCols.GetColumnMap()

	go t.run(context.TODO())

	return t, nil
}

func (t *Tracer) install() error {
	// Enable stats collection
	err := bpfstats.EnableBPFStats()
	if err != nil {
		return err
	}

	t.useFallbackIterator = false

	// To resolve pids, we will first try to iterate using a bpf
	// program. If that doesn't work, we will fall back to scanning
	// all used fds in all processes /proc/$pid/fdinfo/$fd.
	iter, err := piditer.NewTracer()
	if err != nil {
		t.useFallbackIterator = true
	} else {
		t.iter = iter
	}

	return nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	close(t.done)

	if t.iter != nil {
		t.iter.Close()
	}

	bpfstats.DisableBPFStats()
}

func getPidMapFromPids(pids []*piditer.PidIterEntry) map[uint32][]*types.Process {
	pidmap := make(map[uint32][]*types.Process)
	for _, e := range pids {
		if _, ok := pidmap[e.ProgID]; !ok {
			pidmap[e.ProgID] = make([]*types.Process, 0, 1)
		}
		pidmap[e.ProgID] = append(pidmap[e.ProgID], &types.Process{
			Pid:  e.Pid,
			Comm: e.Comm,
		})
	}
	return pidmap
}

func getProgIDFromFile(fn string) (uint32, error) {
	f, err := os.Open(fn)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "prog_id:") {
			progID, _ := strconv.ParseUint(strings.TrimSpace(strings.Split(sc.Text(), ":")[1]), 10, 32)
			return uint32(progID), nil
		}
	}
	return 0, os.ErrNotExist
}

func getPidMapFromProcFs() (map[uint32][]*types.Process, error) {
	processes, err := os.ReadDir(host.HostProcFs)
	if err != nil {
		return nil, err
	}
	pidmap := make(map[uint32][]*types.Process)
	for _, p := range processes {
		if !p.IsDir() {
			continue
		}
		_, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdescs, err := os.ReadDir(filepath.Join(host.HostProcFs, p.Name(), "fdinfo"))
		if err != nil {
			continue
		}
		for _, fd := range fdescs {
			if progID, err := getProgIDFromFile(filepath.Join(host.HostProcFs, p.Name(), "fdinfo", fd.Name())); err == nil {
				pid, err := strconv.ParseUint(p.Name(), 10, 32)
				if err != nil {
					return nil, err
				}
				if pid > math.MaxInt32 {
					return nil, fmt.Errorf("PID (%d) exceeds math.MaxInt32 (%d)", pid, math.MaxInt32)
				}
				if _, ok := pidmap[progID]; !ok {
					pidmap[progID] = make([]*types.Process, 0, 1)
				}
				comm := host.GetProcComm(int(pid))
				pidmap[progID] = append(pidmap[progID], &types.Process{
					Pid:  uint32(pid),
					Comm: strings.TrimSpace(string(comm)),
				})
			}
		}
	}
	return pidmap, nil
}

func (t *Tracer) nextStats() ([]*types.Stats, error) {
	stats := make([]*types.Stats, 0)

	var err error
	var prog *ebpf.Program
	var pids []*piditer.PidIterEntry
	curID := ebpf.ProgramID(0)
	nextID := ebpf.ProgramID(0)

	curStats := make(map[string]programStats)

	mapSizes, err := bpfstats.GetMapsMemUsage()
	if err != nil {
		return nil, fmt.Errorf("getting map memory usage: %w", err)
	}

	numOnlineCPUs, err := numcpus.GetOnline()
	if err != nil {
		return nil, fmt.Errorf("getting number of online cpu: %w", err)
	}

	for {
		nextID, err = ebpf.ProgramGetNextID(curID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return nil, fmt.Errorf("getting next program ID: %w", err)
		}
		if nextID <= curID {
			break
		}
		curID = nextID
		prog, err = ebpf.NewProgramFromID(curID)
		if err != nil {
			continue
		}
		pi, err := prog.Info()
		if err != nil {
			prog.Close()
			continue
		}

		totalMapMemory := uint64(0)
		mapIDs, _ := pi.MapIDs()
		for _, mapID := range mapIDs {
			if size, ok := mapSizes[mapID]; ok {
				totalMapMemory += size
			}
		}

		totalRuntime, _ := pi.Runtime()
		totalRunCount, _ := pi.RunCount()

		curRuntime := int64(0)
		curRunCount := uint64(0)
		cumulativeRuntime := int64(0)
		cumulativeRunCount := uint64(0)

		pkey := fmt.Sprintf("%d-%s", curID, pi.Tag)

		// calculate delta, if possible
		if old, ok := t.prevStats[pkey]; ok {
			curRuntime = int64(totalRuntime) - old.runtime
			curRunCount = totalRunCount - old.runCount
		}
		if t.startStats != nil {
			if start, ok := t.startStats[pkey]; ok {
				cumulativeRuntime = int64(totalRuntime) - start.runtime
				cumulativeRunCount = totalRunCount - start.runCount
			} else {
				cumulativeRuntime = int64(totalRuntime)
				cumulativeRunCount = totalRunCount
			}
		}

		curStats[pkey] = programStats{
			runtime:  int64(totalRuntime),
			runCount: totalRunCount,
		}

		totalCpuUsage := 100 * float64(curRuntime) / float64(t.config.Interval.Nanoseconds())

		stat := &types.Stats{
			ProgramID:          uint32(curID),
			Name:               pi.Name,
			Type:               pi.Type.String(),
			CurrentRuntime:     curRuntime,
			CurrentRunCount:    curRunCount,
			TotalRuntime:       int64(totalRuntime),
			TotalRunCount:      totalRunCount,
			CumulativeRuntime:  cumulativeRuntime,
			CumulativeRunCount: cumulativeRunCount,
			MapMemory:          totalMapMemory,
			MapCount:           uint32(len(mapIDs)),
			TotalCpuUsage:      totalCpuUsage,
			PerCpuUsage:        totalCpuUsage / float64(numOnlineCPUs),
		}

		if t.enricher != nil {
			t.enricher.EnrichNode(&stat.CommonData)
		}

		stats = append(stats, stat)

		prog.Close()
	}

	if t.startStats == nil {
		t.startStats = curStats
	}

	t.prevStats = curStats

	var processMap map[uint32][]*types.Process

	if !t.useFallbackIterator {
		pids, err = t.iter.DumpPids()
		if err != nil {
			return nil, fmt.Errorf("getting pids for programs using iterator: %w", err)
		}
		processMap = getPidMapFromPids(pids)
	} else {
		// Fallback...
		processMap, err = getPidMapFromProcFs()
		if err != nil {
			return nil, fmt.Errorf("getting pids for programs using fallback method: %w", err)
		}
	}

	for i := range stats {
		if tmpProcesses, ok := processMap[stats[i].ProgramID]; ok {
			stats[i].Processes = tmpProcesses
		}
	}

	top.SortStats(stats, t.config.SortBy, &t.colMap)

	return stats, nil
}

func (t *Tracer) run(ctx context.Context) error {
	// Don't use a context with a timeout but a counter to avoid having to deal
	// with two timers: one for the timeout and another for the ticker.
	count := t.config.Iterations
	ticker := time.NewTicker(t.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			// TODO: Once we completely move to use Run instead of NewTracer,
			// we can remove this as nobody will directly call Stop (cleanup).
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stats, err := t.nextStats()
			if err != nil {
				return fmt.Errorf("getting next stats: %w", err)
			}

			n := len(stats)
			if n > t.config.MaxRows {
				n = t.config.MaxRows
			}
			t.eventCallback(&top.Event[types.Stats]{Stats: stats[:n]})

			// Count down only if user requested a finite number of iterations
			// through a timeout.
			if t.config.Iterations > 0 {
				count--
				if count == 0 {
					return nil
				}
			}
		}
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	if err := t.init(gadgetCtx); err != nil {
		return fmt.Errorf("initializing tracer: %w", err)
	}

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	return t.run(gadgetCtx.Context())
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*types.Stats))
	if !ok {
		panic("event handler invalid")
	}

	// TODO: add errorHandler
	t.eventCallback = func(ev *top.Event[types.Stats]) {
		if ev.Error != "" {
			return
		}
		nh(ev.Stats)
	}
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config:    &Config{},
		done:      make(chan bool),
		prevStats: make(map[string]programStats),
	}
	return tracer, nil
}

func (t *Tracer) init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.MaxRows = params.Get(gadgets.ParamMaxRows).AsInt()
	t.config.SortBy = params.Get(gadgets.ParamSortBy).AsStringSlice()
	t.config.Interval = time.Second * time.Duration(params.Get(gadgets.ParamInterval).AsInt())

	var err error
	if t.config.Iterations, err = top.ComputeIterations(t.config.Interval, gadgetCtx.Timeout()); err != nil {
		return err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		return err
	}
	t.colMap = statCols.GetColumnMap()

	return nil
}

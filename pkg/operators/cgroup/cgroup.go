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

// Package cgroup implements an operator that periodically emits cgroup v2 CPU
// throttling statistics. It reads cpu.stat, cpu.max, and (optionally)
// cpu.pressure for every cgroup that has a CPU bandwidth limit, making it
// straightforward to identify which containers/pods are the worst CFS
// throttle offenders.
package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	Name     = "cgroup"
	Priority = -900

	// Configuration keys
	configKeyEnabled       = "operator.cgroup.emitstats"
	configKeyInterval      = "operator.cgroup.interval"
	configKeyFirstInterval = "operator.cgroup.first-interval"
	configKeyCount         = "operator.cgroup.count"

	defaultInterval = 5 * time.Second

	// Field names
	fieldCgroupPath    = "cgroupPath"
	fieldNrPeriods     = "nrPeriods"
	fieldNrThrottled   = "nrThrottled"
	fieldThrottledTime = "throttledTime"
	fieldThrottleRatio = "throttleRatio"
	fieldCPUQuota      = "cpuQuota"
	fieldCPUPeriod     = "cpuPeriod"
	fieldCPULimitCores = "cpuLimitCores"
	fieldPSISomeAvg10  = "psiSomeAvg10"
	fieldPSISomeAvg60  = "psiSomeAvg60"
	fieldMountNsID     = "mountnsid"
)

// cpuStat holds parsed cumulative values from cgroup v2 cpu.stat.
type cpuStat struct {
	nrPeriods     uint64
	nrThrottled   uint64
	throttledUsec uint64
}

// cpuMax holds parsed values from cgroup v2 cpu.max.
type cpuMax struct {
	quota  int64  // -1 means unlimited ("max")
	period uint64 // CFS period in microseconds
}

// psiMetrics holds parsed values from cgroup v2 cpu.pressure.
// Only "some" metrics are included — for CPU cgroups, PSI "full" is always
// identical to "some" because CFS throttling is all-or-nothing.
type psiMetrics struct {
	someAvg10 float64
	someAvg60 float64
	available bool
}

// cgroupInfo holds all collected data for a single cgroup.
type cgroupInfo struct {
	cgroupPath string
	stat       cpuStat
	max        cpuMax
	psi        psiMetrics
	mountNsID  uint64
}

type cgroupOperator struct{}

func (o *cgroupOperator) Name() string                { return Name }
func (o *cgroupOperator) Init(_ *params.Params) error { return nil }
func (o *cgroupOperator) GlobalParams() api.Params    { return api.Params{} }
func (o *cgroupOperator) InstanceParams() api.Params  { return api.Params{} }
func (o *cgroupOperator) Priority() int               { return Priority }

func (o *cgroupOperator) InstantiateDataOperator(
	gadgetCtx operators.GadgetContext,
	instanceParamValues api.ParamValues,
) (operators.DataOperatorInstance, error) {
	config, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("config not found in gadget context")
	}

	viperConfig, ok := config.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("config is not a viper instance")
	}

	if !viperConfig.GetBool(configKeyEnabled) {
		gadgetCtx.Logger().Debug("Cgroup CPU throttle monitoring is disabled")
		return nil, nil
	}

	interval := viperConfig.GetDuration(configKeyInterval)
	if interval <= 0 {
		interval = defaultInterval
	}

	count := viperConfig.GetInt(configKeyCount)
	firstInterval := viperConfig.GetDuration(configKeyFirstInterval)

	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "cgroups")
	if err != nil {
		return nil, fmt.Errorf("registering cgroups data source: %w", err)
	}
	ds.AddAnnotation(api.FetchIntervalAnnotation, interval.String())

	inst := &cgroupOperatorInstance{
		interval:      interval,
		count:         count,
		firstInterval: firstInterval,
		done:          make(chan struct{}),
		dataSource:    ds,
		prevStats:     make(map[string]cpuStat),
	}

	if err := inst.registerFields(ds); err != nil {
		return nil, err
	}
	return inst, nil
}

// cgroupOperatorInstance is the per-run state.
type cgroupOperatorInstance struct {
	interval      time.Duration
	count         int
	firstInterval time.Duration
	dataSource    datasource.DataSource
	done          chan struct{}
	wg            sync.WaitGroup

	// Field accessors
	cgroupPathField    datasource.FieldAccessor
	nrPeriodsField     datasource.FieldAccessor
	nrThrottledField   datasource.FieldAccessor
	throttledTimeField datasource.FieldAccessor
	throttleRatioField datasource.FieldAccessor
	cpuQuotaField      datasource.FieldAccessor
	cpuPeriodField     datasource.FieldAccessor
	cpuLimitCoresField datasource.FieldAccessor
	psiSomeAvg10Field  datasource.FieldAccessor
	psiSomeAvg60Field  datasource.FieldAccessor
	mountNsIDField     datasource.FieldAccessor

	// Delta tracking: previous cumulative cpu.stat values keyed by cgroup path
	prevStats map[string]cpuStat
}

func (inst *cgroupOperatorInstance) registerFields(ds datasource.DataSource) error {
	var err error

	inst.cgroupPathField, err = ds.AddField(fieldCgroupPath, api.Kind_String, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:     "The cgroup v2 path.",
		metadatav1.ColumnsMaxWidthAnnotation: "60",
		metadatav1.ColumnsEllipsisAnnotation: "start",
	}))
	if err != nil {
		return fmt.Errorf("adding cgroupPath field: %w", err)
	}

	inst.nrPeriodsField, err = ds.AddField(fieldNrPeriods, api.Kind_Uint64, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:      "Number of CFS enforcement intervals elapsed in this reporting period.",
		metadatav1.ColumnsAlignmentAnnotation: "right",
		metadatav1.ColumnsMaxWidthAnnotation:  "10",
	}))
	if err != nil {
		return fmt.Errorf("adding nrPeriods field: %w", err)
	}

	inst.nrThrottledField, err = ds.AddField(fieldNrThrottled, api.Kind_Uint64, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:      "Number of times the cgroup was throttled in this reporting period.",
		metadatav1.ColumnsAlignmentAnnotation: "right",
		metadatav1.ColumnsMaxWidthAnnotation:  "12",
	}))
	if err != nil {
		return fmt.Errorf("adding nrThrottled field: %w", err)
	}

	inst.throttledTimeField, err = ds.AddField(fieldThrottledTime+"_raw", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.DescriptionAnnotation:      "Total time spent throttled in this reporting period.",
			metadatav1.ColumnsAlignmentAnnotation: "right",
			metadatav1.ColumnsMaxWidthAnnotation:  "14",
		}),
		datasource.WithTags("type:gadget_duration"),
	)
	if err != nil {
		return fmt.Errorf("adding throttledTime field: %w", err)
	}

	inst.throttleRatioField, err = ds.AddField(fieldThrottleRatio, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:      "Percentage of periods where the cgroup was throttled (0-100) in this reporting period.",
		metadatav1.ColumnsAlignmentAnnotation: "right",
		metadatav1.ColumnsPrecisionAnnotation: "2",
		metadatav1.ColumnsMaxWidthAnnotation:  "8",
	}))
	if err != nil {
		return fmt.Errorf("adding throttleRatio field: %w", err)
	}

	inst.cpuQuotaField, err = ds.AddField(fieldCPUQuota+"_raw", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.DescriptionAnnotation:      "CPU quota per CFS period.",
			metadatav1.ColumnsAlignmentAnnotation: "right",
			metadatav1.ColumnsMaxWidthAnnotation:  "10",
		}),
		datasource.WithTags("type:gadget_duration"),
	)
	if err != nil {
		return fmt.Errorf("adding cpuQuota field: %w", err)
	}

	inst.cpuPeriodField, err = ds.AddField(fieldCPUPeriod+"_raw", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.DescriptionAnnotation:      "CFS period length.",
			metadatav1.ColumnsAlignmentAnnotation: "right",
			metadatav1.ColumnsMaxWidthAnnotation:  "10",
			metadatav1.ColumnsHiddenAnnotation:    "true",
		}),
		datasource.WithTags("type:gadget_duration"),
	)
	if err != nil {
		return fmt.Errorf("adding cpuPeriod field: %w", err)
	}

	inst.cpuLimitCoresField, err = ds.AddField(fieldCPULimitCores, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:      "Effective CPU core limit (quota / period).",
		metadatav1.ColumnsAlignmentAnnotation: "right",
		metadatav1.ColumnsPrecisionAnnotation: "2",
		metadatav1.ColumnsMaxWidthAnnotation:  "8",
	}))
	if err != nil {
		return fmt.Errorf("adding cpuLimitCores field: %w", err)
	}

	// PSI fields
	inst.psiSomeAvg10Field, err = ds.AddField(fieldPSISomeAvg10, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:      "PSI 'some' CPU pressure average over 10 seconds.",
		metadatav1.ColumnsAlignmentAnnotation: "right",
		metadatav1.ColumnsPrecisionAnnotation: "2",
		metadatav1.ColumnsMaxWidthAnnotation:  "8",
	}))
	if err != nil {
		return fmt.Errorf("adding psiSomeAvg10 field: %w", err)
	}

	inst.psiSomeAvg60Field, err = ds.AddField(fieldPSISomeAvg60, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
		metadatav1.DescriptionAnnotation:      "PSI 'some' CPU pressure average over 60 seconds.",
		metadatav1.ColumnsAlignmentAnnotation: "right",
		metadatav1.ColumnsPrecisionAnnotation: "2",
		metadatav1.ColumnsMaxWidthAnnotation:  "8",
	}))
	if err != nil {
		return fmt.Errorf("adding psiSomeAvg60 field: %w", err)
	}

	// Mount namespace ID for container/pod enrichment
	inst.mountNsIDField, err = ds.AddField(fieldMountNsID, api.Kind_Uint64,
		datasource.WithTags("type:gadget_mntns_id"),
		datasource.WithAnnotations(map[string]string{
			metadatav1.TemplateAnnotation: "mntns_id",
		}),
	)
	if err != nil {
		return fmt.Errorf("adding mountnsid field: %w", err)
	}

	return nil
}

func (inst *cgroupOperatorInstance) Name() string { return Name }

func (inst *cgroupOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	inst.wg.Add(1)
	go inst.monitor(gadgetCtx)
	return nil
}

func (inst *cgroupOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	close(inst.done)
	inst.wg.Wait()
	return nil
}

func (inst *cgroupOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (inst *cgroupOperatorInstance) monitor(gadgetCtx operators.GadgetContext) {
	defer inst.wg.Done()

	// First collection establishes baseline for delta computation.
	if err := inst.collectAndEmit(gadgetCtx, false); err != nil {
		gadgetCtx.Logger().Errorf("Error collecting cgroup stats: %v", err)
	}

	if inst.firstInterval > 0 {
		timer := time.NewTimer(inst.firstInterval)
		defer timer.Stop()
		select {
		case <-inst.done:
			return
		case <-timer.C:
			if err := inst.collectAndEmit(gadgetCtx, true); err != nil {
				gadgetCtx.Logger().Errorf("Error collecting cgroup stats: %v", err)
			}
		}
	}

	ticker := time.NewTicker(inst.interval)
	defer ticker.Stop()

	count := 0
	for {
		select {
		case <-inst.done:
			return
		case <-ticker.C:
			if err := inst.collectAndEmit(gadgetCtx, true); err != nil {
				gadgetCtx.Logger().Errorf("Error collecting cgroup stats: %v", err)
			}
			count++
			if inst.count > 0 && count >= inst.count {
				return
			}
		}
	}
}

// discoverCgroupsFn is the function used to discover cgroups. It defaults to
// discoverCgroups and can be replaced in tests.
var discoverCgroupsFn = discoverCgroups

// collectAndEmit discovers cgroups with CPU bandwidth limits, reads their
// throttling stats, computes per-interval deltas, and emits the results.
// When emit is false (baseline collection), only prevStats is updated —
// no packets are allocated or emitted.
func (inst *cgroupOperatorInstance) collectAndEmit(gadgetCtx operators.GadgetContext, emit bool) error {
	infos, err := discoverCgroupsFn(gadgetCtx)
	if err != nil {
		return fmt.Errorf("discovering cgroups: %w", err)
	}

	newPrevStats := make(map[string]cpuStat, len(infos))

	if !emit {
		for _, info := range infos {
			newPrevStats[info.cgroupPath] = info.stat
		}
		inst.prevStats = newPrevStats
		return nil
	}

	packetArray, err := inst.dataSource.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating packet array: %w", err)
	}

	for _, info := range infos {
		newPrevStats[info.cgroupPath] = info.stat

		// Compute deltas from the previous interval
		var deltaPeriods, deltaThrottled, deltaThrottledUsec uint64
		if prev, ok := inst.prevStats[info.cgroupPath]; ok {
			// Guard against counter resets (e.g. cgroup destroyed and recreated)
			if info.stat.nrPeriods >= prev.nrPeriods {
				deltaPeriods = info.stat.nrPeriods - prev.nrPeriods
			}
			if info.stat.nrThrottled >= prev.nrThrottled {
				deltaThrottled = info.stat.nrThrottled - prev.nrThrottled
			}
			if info.stat.throttledUsec >= prev.throttledUsec {
				deltaThrottledUsec = info.stat.throttledUsec - prev.throttledUsec
			}
		} else {
			deltaPeriods = info.stat.nrPeriods
			deltaThrottled = info.stat.nrThrottled
			deltaThrottledUsec = info.stat.throttledUsec
		}

		// Skip cgroups with no CFS activity in this interval
		if deltaPeriods == 0 && deltaThrottled == 0 {
			continue
		}

		var throttleRatio float64
		if deltaPeriods > 0 {
			throttleRatio = float64(deltaThrottled) / float64(deltaPeriods) * 100
		}

		var cpuLimitCores float64
		if info.max.quota > 0 && info.max.period > 0 {
			cpuLimitCores = float64(info.max.quota) / float64(info.max.period)
		}

		packet := packetArray.New()

		inst.cgroupPathField.PutString(packet, info.cgroupPath)
		inst.nrPeriodsField.PutUint64(packet, deltaPeriods)
		inst.nrThrottledField.PutUint64(packet, deltaThrottled)
		inst.throttledTimeField.PutUint64(packet, deltaThrottledUsec*1000) // µs → ns for gadget_duration
		inst.throttleRatioField.PutFloat64(packet, throttleRatio)
		inst.cpuQuotaField.PutUint64(packet, uint64(info.max.quota)*1000) // µs → ns for gadget_duration
		inst.cpuPeriodField.PutUint64(packet, info.max.period*1000)       // µs → ns for gadget_duration
		inst.cpuLimitCoresField.PutFloat64(packet, cpuLimitCores)

		if info.psi.available {
			inst.psiSomeAvg10Field.PutFloat64(packet, info.psi.someAvg10)
			inst.psiSomeAvg60Field.PutFloat64(packet, info.psi.someAvg60)
		}

		inst.mountNsIDField.PutUint64(packet, info.mountNsID)
		packetArray.Append(packet)
	}

	inst.prevStats = newPrevStats
	return inst.dataSource.EmitAndRelease(packetArray)
}

// ---------------------------------------------------------------------------
// Cgroup discovery
// ---------------------------------------------------------------------------

// discoverCgroups iterates /proc to find all unique cgroup v2 paths, then
// reads CPU throttling data for those that have a bandwidth limit (non-"max"
// quota in cpu.max).
func discoverCgroups(gadgetCtx operators.GadgetContext) ([]cgroupInfo, error) {
	entries, err := os.ReadDir(host.HostProcFs)
	if err != nil {
		return nil, fmt.Errorf("reading proc directory: %w", err)
	}

	// Map each unique cgroup v2 path to a representative PID.
	type pidCgroupEntry struct {
		pid  int
		path string
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	cgroupMap := make(map[string]int) // cgroup path → representative PID
	pidQueue := make(chan int, 64)

	workers := runtime.NumCPU()
	for range workers {
		wg.Go(func() {
			for pid := range pidQueue {
				_, v2Path, err := cgroups.GetCgroupPaths(pid)
				if err != nil || v2Path == "" {
					continue
				}
				mu.Lock()
				if _, exists := cgroupMap[v2Path]; !exists {
					cgroupMap[v2Path] = pid
				}
				mu.Unlock()
			}
		})
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		pidQueue <- pid
	}
	close(pidQueue)
	wg.Wait()

	// Read stats for each unique cgroup that has a CPU bandwidth limit.
	var infos []cgroupInfo
	for cgPath, pid := range cgroupMap {
		fullPath, err := cgroups.CgroupPathV2AddMountpoint(cgPath)
		if err != nil {
			gadgetCtx.Logger().Debugf("Skipping cgroup %s: %v", cgPath, err)
			continue
		}

		cpuMax, err := readCPUMax(fullPath)
		if err != nil {
			gadgetCtx.Logger().Debugf("Skipping cgroup %s: cannot read cpu.max: %v", cgPath, err)
			continue
		}

		// Skip cgroups without an explicit CPU limit.
		if cpuMax.quota == -1 {
			continue
		}

		stat, err := readCPUStat(fullPath)
		if err != nil {
			gadgetCtx.Logger().Debugf("Skipping cgroup %s: cannot read cpu.stat: %v", cgPath, err)
			continue
		}

		psi := readCPUPressure(fullPath)
		mntNsID, _ := containerutils.GetMntNs(pid)

		infos = append(infos, cgroupInfo{
			cgroupPath: cgPath,
			stat:       stat,
			max:        cpuMax,
			psi:        psi,
			mountNsID:  mntNsID,
		})
	}

	return infos, nil
}

// ---------------------------------------------------------------------------
// Cgroup v2 file parsers
// ---------------------------------------------------------------------------

// readCPUStat parses the cpu.stat file.
//
// Example content:
//
//	usage_usec 123456
//	user_usec 100000
//	system_usec 23456
//	nr_periods 1000
//	nr_throttled 50
//	throttled_usec 500000
func readCPUStat(cgroupFullPath string) (cpuStat, error) {
	var stat cpuStat

	data, err := os.ReadFile(filepath.Join(cgroupFullPath, "cpu.stat"))
	if err != nil {
		return stat, err
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "nr_periods":
			stat.nrPeriods = val
		case "nr_throttled":
			stat.nrThrottled = val
		case "throttled_usec":
			stat.throttledUsec = val
		}
	}

	return stat, nil
}

// readCPUMax parses the cpu.max file.
//
// Format: "<quota> <period>" or "max <period>"
func readCPUMax(cgroupFullPath string) (cpuMax, error) {
	var result cpuMax

	data, err := os.ReadFile(filepath.Join(cgroupFullPath, "cpu.max"))
	if err != nil {
		return result, err
	}

	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) != 2 {
		return result, fmt.Errorf("unexpected cpu.max format: %q", string(data))
	}

	if fields[0] == "max" {
		result.quota = -1
	} else {
		quota, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return result, fmt.Errorf("parsing quota: %w", err)
		}
		result.quota = quota
	}

	period, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return result, fmt.Errorf("parsing period: %w", err)
	}
	result.period = period

	return result, nil
}

// readCPUPressure parses the cpu.pressure file. Returns a zero-value
// psiMetrics (with available=false) if the file cannot be read, so
// callers never need to treat a missing PSI file as an error.
//
// Example content:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=0
func readCPUPressure(cgroupFullPath string) psiMetrics {
	var psi psiMetrics

	data, err := os.ReadFile(filepath.Join(cgroupFullPath, "cpu.pressure"))
	if err != nil {
		return psi
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "some ") {
			psi.someAvg10, psi.someAvg60 = parsePSILine(line)
			psi.available = true
		}
	}

	return psi
}

// parsePSILine extracts avg10 and avg60 from a PSI line such as:
//
//	some avg10=0.50 avg60=1.20 avg300=0.80 total=12345
func parsePSILine(line string) (avg10, avg60 float64) {
	for field := range strings.FieldsSeq(line) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}
		switch parts[0] {
		case "avg10":
			avg10 = val
		case "avg60":
			avg60 = val
		}
	}
	return
}

// Operator is the global instance registered via init().
var Operator = &cgroupOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}

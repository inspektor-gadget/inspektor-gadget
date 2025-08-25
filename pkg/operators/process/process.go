// Copyright 2024-2025 The Inspektor Gadget authors
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

// Package process implements an operator that emits events about running processes
// with CPU and RAM usage information.
package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"github.com/tklauser/numcpus"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	processhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/process-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	Name = "process"

	// Priority defines the operator's priority
	Priority = -1000

	// Configuration keys
	configKeyEnabled       = "operator.process.emitstats"
	configKeyInterval      = "operator.process.interval"
	configKeyFirstInterval = "operator.process.first-interval"
	configKeyFields        = "operator.process.fields"

	// Default values
	defaultInterval = 60 * time.Second

	// Field names
	fieldPID              = "pid"
	fieldPPID             = "ppid"
	fieldComm             = "comm"
	fieldNice             = "nice"
	fieldPriority         = "priority"
	fieldCPUTime          = "cpuTime"
	fieldCPUTimeStr       = "cpuTimeStr"
	fieldCPUUsage         = "cpuUsage"
	fieldCPUUsageRelative = "cpuUsageRelative"
	fieldMemoryRSS        = "memoryRSS"
	fieldMemoryVirtual    = "memoryVirtual"
	fieldMemoryRelative   = "memoryRelative"
	fieldMemoryShared     = "memoryShared"
	fieldThreadCount      = "threadCount"
	fieldState            = "state"
	fieldUid              = "uid"
	fieldStartTime        = "startTime"
	fieldStartTimeStr     = "startTimeStr"
	fieldMountNsID        = "mountnsid"
)

type processOperator struct{}

func (p *processOperator) Name() string {
	return Name
}

func (p *processOperator) Init(globalParams *params.Params) error {
	return nil
}

func (p *processOperator) GlobalParams() api.Params {
	return api.Params{}
}

func (p *processOperator) InstanceParams() api.Params {
	return api.Params{}
}

func (p *processOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	// Get configuration from viper
	config, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("config not found in gadget context")
	}

	viperConfig, ok := config.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("config is not a viper instance")
	}

	// Check if process monitoring is enabled
	enabled := viperConfig.GetBool(configKeyEnabled)
	if !enabled {
		gadgetCtx.Logger().Debug("Process monitoring is disabled")
		return nil, nil
	}

	// Get the interval from config or use default
	interval := viperConfig.GetDuration(configKeyInterval)
	if interval <= 0 {
		interval = defaultInterval
		gadgetCtx.Logger().Debugf("Using default interval: %s", interval)
	}

	firstInterval := viperConfig.GetDuration(configKeyFirstInterval)

	// Get fields from config
	fields := viperConfig.GetStringSlice(configKeyFields)

	// If no fields are specified, enable all fields by default
	if len(fields) == 0 {
		gadgetCtx.Logger().Debug("No fields specified for internal datasource 'processes', enabling all fields")
		fields = []string{
			fieldPID,
			fieldPPID,
			fieldComm,
			fieldPriority,
			fieldNice,
			fieldCPUUsage,
			fieldCPUUsageRelative,
			fieldMemoryRSS,
			fieldMemoryVirtual,
			fieldMemoryShared,
			fieldMemoryRelative,
			fieldThreadCount,
			fieldState,
			fieldUid,
			fieldStartTime,
			fieldCPUTime,
		}
	}

	// Create a data source for process information
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "processes")
	if err != nil {
		return nil, fmt.Errorf("registering processes data source: %w", err)
	}

	ds.AddAnnotation(api.FetchIntervalAnnotation, interval.String())

	instance := &processOperatorInstance{
		interval:      interval,
		firstInterval: firstInterval,
		done:          make(chan struct{}),
		dataSource:    ds,
	}

	// Add fields to the data source based on enabled fields
	// PID field is always added (it's required)
	instance.pidField, err = ds.AddField(fieldPID, api.Kind_Int32, datasource.WithAnnotations(map[string]string{
		metadatav1.TemplateAnnotation: "pid",
	}))
	if err != nil {
		return nil, fmt.Errorf("adding pid field: %w", err)
	}

	requireCPUInfo := false

	for _, field := range fields {
		switch field {
		case fieldPPID:
			instance.ppidField, err = ds.AddField(fieldPPID, api.Kind_Int32, datasource.WithAnnotations(map[string]string{
				metadatav1.TemplateAnnotation: "ppid",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding ppid field: %w", err)
			}
		case fieldComm:
			instance.commField, err = ds.AddField(fieldComm, api.Kind_String, datasource.WithAnnotations(map[string]string{
				metadatav1.TemplateAnnotation: "comm",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding comm field: %w", err)
			}
		case fieldNice:
			instance.niceField, err = ds.AddField(fieldNice, api.Kind_Int8, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.DescriptionAnnotation:      "The nice value of the process.",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding nice field: %w", err)
			}
			requireCPUInfo = true
		case fieldPriority:
			instance.priorityField, err = ds.AddField(fieldPriority, api.Kind_Int8, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.DescriptionAnnotation:      "The priority of the process.",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding priority field: %w", err)
			}
			requireCPUInfo = true
		case fieldCPUTime:
			instance.cpuTimeField, err = ds.AddField(fieldCPUTime, api.Kind_Int64, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsHiddenAnnotation: "true",
				metadatav1.DescriptionAnnotation:   "Total CPU time",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding cpuTime field: %w", err)
			}
			instance.cpuTimeStrField, err = ds.AddField(fieldCPUTimeStr, api.Kind_String, datasource.WithAnnotations(map[string]string{
				metadatav1.DescriptionAnnotation:      "Total CPU time, formatted as duration",
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.ColumnsMaxWidthAnnotation:  "12",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding cpuTimeStr field: %w", err)
			}
		case fieldCPUUsage:
			instance.cpuField, err = ds.AddField(fieldCPUUsage, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsPrecisionAnnotation: "1",
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.DescriptionAnnotation:      "The CPU usage of the process as a percentage.",
				metadatav1.ColumnsMaxWidthAnnotation:  "8",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding cpuUsage field: %w", err)
			}
			requireCPUInfo = true
		case fieldCPUUsageRelative:
			instance.cpuRelativeField, err = ds.AddField(fieldCPUUsageRelative, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsPrecisionAnnotation: "1",
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.DescriptionAnnotation:      "The CPU usage percentage relative to the number of CPUs available.",
				metadatav1.ColumnsMaxWidthAnnotation:  "8",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding cpuUsageRelative field: %w", err)
			}
			requireCPUInfo = true
		case fieldMemoryRSS:
			instance.memoryRSSField, err = ds.AddField(fieldMemoryRSS+"_raw", api.Kind_Uint64,
				datasource.WithAnnotations(map[string]string{
					metadatav1.ColumnsAlignmentAnnotation: "right",
					metadatav1.DescriptionAnnotation:      "The Resident Set Size (RSS) of the process in bytes. This represents the portion of memory occupied by a process that is held in main memory (RAM).",
				}),
				datasource.WithTags("type:gadget_bytes"),
			)
			if err != nil {
				return nil, fmt.Errorf("adding memoryRSS field: %w", err)
			}
		case fieldMemoryVirtual:
			instance.memoryVirtualField, err = ds.AddField(fieldMemoryVirtual+"_raw", api.Kind_Uint64,
				datasource.WithAnnotations(map[string]string{
					metadatav1.ColumnsAlignmentAnnotation: "right",
					metadatav1.DescriptionAnnotation:      "The Virtual Memory Size of the process in bytes. This represents the total amount of virtual memory used by the process.",
				}),
				datasource.WithTags("type:gadget_bytes"),
			)
			if err != nil {
				return nil, fmt.Errorf("adding memoryVirtual field: %w", err)
			}
		case fieldMemoryRelative:
			instance.memoryRelativeField, err = ds.AddField(fieldMemoryRelative, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.ColumnsPrecisionAnnotation: "1",
				metadatav1.DescriptionAnnotation:      "Percentage of RSS memory used relative to available memory.",
				metadatav1.ColumnsMaxWidthAnnotation:  "8",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding memoryRelative field: %w", err)
			}
		case fieldMemoryShared:
			instance.memorySharedField, err = ds.AddField(fieldMemoryShared+"_raw", api.Kind_Uint64,
				datasource.WithAnnotations(map[string]string{
					metadatav1.ColumnsAlignmentAnnotation: "right",
					metadatav1.DescriptionAnnotation:      "The Shared Memory Size of the process in bytes.",
				}),
				datasource.WithTags("type:gadget_bytes"),
			)
			if err != nil {
				return nil, fmt.Errorf("adding memoryShared field: %w", err)
			}
		case fieldThreadCount:
			instance.threadCountField, err = ds.AddField(fieldThreadCount, api.Kind_Int32, datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsAlignmentAnnotation: "right",
				metadatav1.DescriptionAnnotation:      "The number of threads used by the process.",
				metadatav1.ColumnsMaxWidthAnnotation:  "11",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding threadCount field: %w", err)
			}
		case fieldState:
			instance.stateField, err = ds.AddField(fieldState, api.Kind_String, datasource.WithAnnotations(map[string]string{
				metadatav1.DescriptionAnnotation:     "The state of the process (e.g., \"R\" for running, \"S\" for sleeping, \"Z\" for zombie, etc.).",
				metadatav1.ValueOneOfAnnotation:      "R,S,D,Z,T,t,W,X,x,K,W,P,I",
				metadatav1.ColumnsMaxWidthAnnotation: "5",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding state field: %w", err)
			}
		case fieldUid:
			instance.uidField, err = ds.AddField(fieldUid, api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
				metadatav1.TemplateAnnotation: "uid",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding uid field: %w", err)
			}
		case fieldStartTime, fieldStartTimeStr:
			instance.startTimeField, err = ds.AddField(fieldStartTime, api.Kind_Uint64, datasource.WithAnnotations(map[string]string{
				metadatav1.DescriptionAnnotation:   "The time when the process started, represented as clock ticks since system boot.",
				metadatav1.ColumnsHiddenAnnotation: "true",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding startTime field: %w", err)
			}

			// Add the formatted start time field
			instance.startTimeStrField, err = ds.AddField(fieldStartTimeStr, api.Kind_String, datasource.WithAnnotations(map[string]string{
				metadatav1.DescriptionAnnotation:     "The time when the process started, represented as a formatted date-time string in RFC3339 format (e.g., \"2023-06-15T14:30:45Z\").",
				metadatav1.ColumnsEllipsisAnnotation: "start",
				metadatav1.ColumnsMaxWidthAnnotation: "25",
			}))
			if err != nil {
				return nil, fmt.Errorf("adding startTimeStr field: %w", err)
			}
		}
	}

	// Add mount namespace ID field (always added)
	instance.mountNsIDField, err = ds.AddField(fieldMountNsID, api.Kind_Uint64, datasource.WithTags("type:gadget_mntns_id"), datasource.WithAnnotations(map[string]string{
		metadatav1.TemplateAnnotation: "mntns_id",
	}))
	if err != nil {
		return nil, fmt.Errorf("adding mountnsid field: %w", err)
	}

	// Initialize CPU usage tracking if needed
	if requireCPUInfo {
		instance.lastCPUTimes = make(map[int]uint64)
		instance.lastSampleTime = time.Now()
	}

	return instance, nil
}

func (p *processOperator) Priority() int {
	return Priority
}

type processOperatorInstance struct {
	interval            time.Duration
	firstInterval       time.Duration
	dataSource          datasource.DataSource
	done                chan struct{}
	wg                  sync.WaitGroup
	pidField            datasource.FieldAccessor
	ppidField           datasource.FieldAccessor
	commField           datasource.FieldAccessor
	priorityField       datasource.FieldAccessor
	niceField           datasource.FieldAccessor
	cpuField            datasource.FieldAccessor
	cpuTimeField        datasource.FieldAccessor
	cpuTimeStrField     datasource.FieldAccessor
	cpuRelativeField    datasource.FieldAccessor
	memoryRSSField      datasource.FieldAccessor
	memoryVirtualField  datasource.FieldAccessor
	memorySharedField   datasource.FieldAccessor
	memoryRelativeField datasource.FieldAccessor
	threadCountField    datasource.FieldAccessor
	stateField          datasource.FieldAccessor
	uidField            datasource.FieldAccessor
	startTimeField      datasource.FieldAccessor
	startTimeStrField   datasource.FieldAccessor
	mountNsIDField      datasource.FieldAccessor
	// For relative memory
	totalMemory uint64
	// For CPU usage calculation
	lastCPUTimes   map[int]uint64
	lastSampleTime time.Time
	numCPU         int
	// System boot time
	bootTime time.Time
}

func (p *processOperatorInstance) Name() string {
	return Name
}

func (p *processOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	// Get the system boot time
	bootTime, err := getBootTime()
	if err != nil {
		gadgetCtx.Logger().Warn("Could not determine system boot time, using current time: %v", err)
	}

	p.bootTime = bootTime

	// Start the process monitoring goroutine
	p.wg.Add(1)
	go p.monitorProcesses(gadgetCtx)

	return nil
}

func getBootTime() (time.Time, error) {
	// Read /proc/stat to get the boot time
	statFile, err := os.Open(filepath.Join(host.HostProcFs, "stat"))
	if err != nil {
		return time.Now(), fmt.Errorf("opening /proc/stat: %w", err)
	}
	defer statFile.Close()

	scanner := bufio.NewScanner(statFile)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		bootTimeSec, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		return time.Unix(bootTimeSec, 0), nil
	}

	return time.Now(), fmt.Errorf("determining boot time")
}

func (p *processOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	close(p.done)
	p.wg.Wait()
	gadgetCtx.Logger().Debug("Process monitoring stopped")
	return nil
}

func (p *processOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (p *processOperatorInstance) TotalMemory() uint64 {
	return p.totalMemory
}

func (p *processOperatorInstance) NumCPU() int {
	return p.numCPU
}

func (p *processOperatorInstance) monitorProcesses(gadgetCtx operators.GadgetContext) {
	defer p.wg.Done()

	// Collect the first round without emitting to be able to calculate the CPU usage deltas in the
	// second run after p.interval
	err := p.collectProcessInfo(gadgetCtx, false)
	if err != nil {
		gadgetCtx.Logger().Errorf("Error collecting process info: %v", err)
	}

	// Run a first interval, if configured, to provide early data
	if p.firstInterval > 0 {
		timer := time.NewTimer(p.firstInterval)
		defer timer.Stop()
		select {
		case <-p.done:
			return
		case <-timer.C:
			err := p.collectProcessInfo(gadgetCtx, true)
			if err != nil {
				gadgetCtx.Logger().Errorf("Error collecting process info: %v", err)
			}
		}
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			err := p.collectProcessInfo(gadgetCtx, true)
			if err != nil {
				gadgetCtx.Logger().Errorf("Error collecting process info: %v", err)
			}
		}
	}
}

func (p *processOperatorInstance) collectProcessInfo(gadgetCtx operators.GadgetContext, emit bool) error {
	// Get the current time for CPU usage calculation if needed
	var timeDelta float64
	if p.cpuField != nil {
		currentTime := time.Now()
		timeDelta = currentTime.Sub(p.lastSampleTime).Seconds()
		defer func() { p.lastSampleTime = currentTime }()
	}

	var err error
	p.numCPU, err = numcpus.GetOnline()
	if err != nil {
		return fmt.Errorf("getting number of CPUs: %w", err)
	}

	p.totalMemory, err = processhelpers.GetTotalMemory()
	if err != nil {
		return fmt.Errorf("getting total memory: %w", err)
	}

	// Read /proc directory to get all processes
	entries, err := os.ReadDir(host.HostProcFs)
	if err != nil {
		return fmt.Errorf("reading /proc directory: %w", err)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	pidQueue := make(chan int, 64)

	var processes []processhelpers.ProcessInfo

	// Fetch process information in parallel
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range pidQueue {
				// Get process information
				procInfo, err := processhelpers.GetProcessInfo(pid, timeDelta, p)
				if err != nil {
					// Skip processes that we can't read (they might have terminated)
					gadgetCtx.Logger().Debugf("Skipping process %d: %v", pid, err)
					continue
				}
				procInfo.MountNsID, _ = containerutils.GetMntNs(pid)
				mu.Lock()
				processes = append(processes, procInfo)
				mu.Unlock()
			}
		}()
	}

	for _, entry := range entries {
		// Skip non-directories and non-numeric names (not PIDs)
		if !entry.IsDir() {
			continue
		}

		pid64, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			// Not a process directory
			continue
		}
		pid := int(pid64)

		pidQueue <- pid
	}
	close(pidQueue)
	wg.Wait()

	// Reset lastCPUTime
	p.lastCPUTimes = make(map[int]uint64, len(processes))
	for _, procInfo := range processes {
		p.lastCPUTimes[procInfo.PID] = procInfo.CPUTime
	}

	// Create a packet array to hold all processes
	packetArray, err := p.dataSource.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating packet array: %w", err)
	}

	// Add each process to the packet array
	for _, proc := range processes {
		// Create a new data element for the array
		packet := packetArray.New()

		// PID field is always emitted (it's required)
		p.pidField.PutInt32(packet, int32(proc.PID))

		// Emit optional fields if their accessors are not nil
		if p.ppidField != nil {
			p.ppidField.PutInt32(packet, int32(proc.PPID))
		}

		if p.commField != nil {
			p.commField.PutString(packet, proc.Comm)
		}

		if p.priorityField != nil {
			p.priorityField.PutInt8(packet, int8(proc.Priority))
		}

		if p.niceField != nil {
			p.niceField.PutInt8(packet, int8(proc.Nice))
		}

		if p.cpuField != nil {
			p.cpuField.PutFloat64(packet, proc.CPUUsage)
		}

		if p.cpuRelativeField != nil {
			p.cpuRelativeField.PutFloat64(packet, proc.CPUUsageRelative)
		}

		if p.memoryRSSField != nil {
			p.memoryRSSField.PutUint64(packet, proc.MemoryRSS)
		}

		if p.memoryVirtualField != nil {
			p.memoryVirtualField.PutUint64(packet, proc.MemoryVirtual)
		}

		if p.memorySharedField != nil {
			p.memorySharedField.PutUint64(packet, proc.MemoryShared)
		}

		if p.memoryRelativeField != nil {
			p.memoryRelativeField.PutFloat64(packet, proc.MemoryRelative)
		}

		if p.threadCountField != nil {
			p.threadCountField.PutInt32(packet, int32(proc.ThreadCount))
		}

		if p.stateField != nil {
			p.stateField.PutString(packet, proc.State)
		}

		if p.uidField != nil {
			p.uidField.PutUint32(packet, proc.Uid)
		}

		if p.startTimeField != nil {
			p.startTimeField.PutUint64(packet, proc.StartTime)
			p.startTimeStrField.PutString(packet, proc.StartTimeStr.Format(time.RFC3339))
		}

		if p.cpuTimeField != nil {
			p.cpuTimeField.PutUint64(packet, proc.CPUTime)

			d := time.Duration(proc.CPUTime) * time.Millisecond * 10
			mins := int(d.Minutes())
			secs := int(d.Seconds()) % 60
			ms := int(d.Milliseconds() % 1000)
			p.cpuTimeStrField.PutString(packet, strconv.Itoa(mins)+":"+pad2(secs)+"."+pad3(ms))
		}

		// Always emit mount namespace ID
		p.mountNsIDField.PutUint64(packet, proc.MountNsID)

		// Append the packet to the array
		packetArray.Append(packet)
	}

	if emit {
		// Emit the packet array with all processes
		err = p.dataSource.EmitAndRelease(packetArray)
		if err != nil {
			return fmt.Errorf("emitting packet array: %w", err)
		}
	} else {
		p.dataSource.Release(packetArray)
	}

	return nil
}

func (p *processOperatorInstance) WithCPUUsage() bool {
	return p.cpuField != nil
}

func (p *processOperatorInstance) WithCPUUsageRelative() bool {
	return p.cpuRelativeField != nil
}

func (p *processOperatorInstance) WithComm() bool {
	return p.commField != nil
}

func (p *processOperatorInstance) WithPPID() bool {
	return p.ppidField != nil
}

func (p *processOperatorInstance) WithState() bool {
	return p.stateField != nil
}

func (p *processOperatorInstance) WithUID() bool {
	return p.uidField != nil
}

func (p *processOperatorInstance) WithVmSize() bool {
	return p.memoryVirtualField != nil
}

func (p *processOperatorInstance) WithVmRSS() bool {
	return p.memoryRSSField != nil
}

func (p *processOperatorInstance) WithMemoryRelative() bool {
	return p.memoryRelativeField != nil
}

func (p *processOperatorInstance) WithThreadCount() bool {
	return p.threadCountField != nil
}

func (p *processOperatorInstance) WithStartTime() bool {
	return p.startTimeField != nil
}

func (p *processOperatorInstance) LastCPUTime(pid int) (uint64, bool) {
	t, ok := p.lastCPUTimes[pid]
	return t, ok
}

func (p *processOperatorInstance) BootTime() time.Time {
	return p.bootTime
}

// Operator is the global instance of the process operator
var Operator = &processOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}

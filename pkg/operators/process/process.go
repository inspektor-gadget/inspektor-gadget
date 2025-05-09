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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	Name = "process"

	// Priority defines the operator's priority
	Priority = -1000

	// Configuration keys
	configKeyEnabled  = "internalDataSources.processes.enabled"
	configKeyInterval = "internalDataSources.processes.interval"
	configKeyFields   = "internalDataSources.processes.fields"

	// Default values
	defaultInterval = 60 * time.Second

	// Field names
	fieldPID           = "pid"
	fieldPPID          = "ppid"
	fieldCommand       = "command"
	fieldCPUUsage      = "cpuUsage"
	fieldMemoryRSS     = "memoryRSS"
	fieldMemoryVirtual = "memoryVirtual"
	fieldThreadCount   = "threadCount"
	fieldState         = "state"
	fieldUid           = "uid"
	fieldStartTime     = "startTime"
	fieldStartTimeStr  = "startTimeStr"
	fieldMountNsID     = "mountnsid"

	// Clock ticks per second (typically 100 on most Linux systems)
	clockTicksPerSecond = 100
)

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	PID           int       `json:"pid"`
	PPID          int       `json:"ppid"`
	Command       string    `json:"command"`
	CPUUsage      float64   `json:"cpuUsage"`      // CPU usage in percentage
	MemoryRSS     uint64    `json:"memoryRSS"`     // Resident Set Size in bytes
	MemoryVirtual uint64    `json:"memoryVirtual"` // Virtual memory size in bytes
	ThreadCount   int       `json:"threadCount"`   // Number of threads
	State         string    `json:"state"`         // Process state (R: running, S: sleeping, etc.)
	Uid           uint32    `json:"uid"`           // UID of the process owner
	StartTime     uint64    `json:"startTime"`     // Process start time (clock ticks since system boot)
	StartTimeStr  time.Time `json:"startTimeStr"`  // Process start time as a formatted string
	MountNsID     uint64    `json:"mountnsid"`     // Mount namespace ID
}

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

	// Get the enabled fields from config
	enabledFields := make(map[string]bool)

	// Get fields from config
	fields := viperConfig.GetStringSlice(configKeyFields)

	// If no fields are specified, enable all fields by default
	if len(fields) == 0 {
		gadgetCtx.Logger().Debug("No fields specified, enabling all fields")
		enabledFields[fieldPID] = true
		enabledFields[fieldPPID] = true
		enabledFields[fieldCommand] = true
		enabledFields[fieldCPUUsage] = true
		enabledFields[fieldMemoryRSS] = true
		enabledFields[fieldMemoryVirtual] = true
		enabledFields[fieldThreadCount] = true
		enabledFields[fieldState] = true
		enabledFields[fieldUid] = true
		enabledFields[fieldStartTime] = true
	} else {
		// Enable only the specified fields
		for _, field := range fields {
			enabledFields[field] = true
		}

		// PID field is always required
		enabledFields[fieldPID] = true

		gadgetCtx.Logger().Debugf("Enabled fields: %v", fields)
	}

	// Create a data source for process information
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "processes")
	if err != nil {
		return nil, fmt.Errorf("registering processes data source: %w", err)
	}

	instance := &processOperatorInstance{
		interval:      interval,
		enabledFields: enabledFields,
		done:          make(chan struct{}),
		dataSource:    ds,
	}

	// Add fields to the data source based on enabled fields
	// PID field is always added (it's required)
	instance.pidField, err = ds.AddField(fieldPID, api.Kind_Int32)
	if err != nil {
		return nil, fmt.Errorf("adding pid field: %w", err)
	}

	// Add optional fields if enabled
	if instance.enabledFields[fieldPPID] {
		instance.ppidField, err = ds.AddField(fieldPPID, api.Kind_Int32)
		if err != nil {
			return nil, fmt.Errorf("adding ppid field: %w", err)
		}
	}

	if instance.enabledFields[fieldCommand] {
		instance.cmdField, err = ds.AddField(fieldCommand, api.Kind_String)
		if err != nil {
			return nil, fmt.Errorf("adding command field: %w", err)
		}
	}

	if instance.enabledFields[fieldCPUUsage] {
		instance.cpuField, err = ds.AddField(fieldCPUUsage, api.Kind_Float64)
		if err != nil {
			return nil, fmt.Errorf("adding cpuUsage field: %w", err)
		}
	}

	if instance.enabledFields[fieldMemoryRSS] {
		instance.memoryRSSField, err = ds.AddField(fieldMemoryRSS, api.Kind_Uint64)
		if err != nil {
			return nil, fmt.Errorf("adding memoryRSS field: %w", err)
		}
	}

	if instance.enabledFields[fieldMemoryVirtual] {
		instance.memoryVirtualField, err = ds.AddField(fieldMemoryVirtual, api.Kind_Uint64)
		if err != nil {
			return nil, fmt.Errorf("adding memoryVirtual field: %w", err)
		}
	}

	if instance.enabledFields[fieldThreadCount] {
		instance.threadCountField, err = ds.AddField(fieldThreadCount, api.Kind_Int32)
		if err != nil {
			return nil, fmt.Errorf("adding threadCount field: %w", err)
		}
	}

	if instance.enabledFields[fieldState] {
		instance.stateField, err = ds.AddField(fieldState, api.Kind_String)
		if err != nil {
			return nil, fmt.Errorf("adding state field: %w", err)
		}
	}

	if instance.enabledFields[fieldUid] {
		instance.usernameField, err = ds.AddField(fieldUid, api.Kind_Uint32)
		if err != nil {
			return nil, fmt.Errorf("adding username field: %w", err)
		}
	}

	if instance.enabledFields[fieldStartTime] {
		instance.startTimeField, err = ds.AddField(fieldStartTime, api.Kind_Uint64)
		if err != nil {
			return nil, fmt.Errorf("adding startTime field: %w", err)
		}

		// Add the formatted start time field
		instance.startTimeStrField, err = ds.AddField(fieldStartTimeStr, api.Kind_String)
		if err != nil {
			return nil, fmt.Errorf("adding startTimeStr field: %w", err)
		}
	}

	// Add mount namespace ID field (always added)
	instance.mountNsIDField, err = ds.AddField(fieldMountNsID, api.Kind_Uint64, datasource.WithTags("type:gadget_mntns_id"))
	if err != nil {
		return nil, fmt.Errorf("adding mountnsid field: %w", err)
	}

	// Initialize CPU usage tracking if needed
	if instance.enabledFields[fieldCPUUsage] {
		instance.lastCPUTimes = make(map[int]uint64)
		instance.lastSampleTime = time.Now()
	}

	return instance, nil
}

func (p *processOperator) Priority() int {
	return Priority
}

type processOperatorInstance struct {
	interval           time.Duration
	dataSource         datasource.DataSource
	done               chan struct{}
	wg                 sync.WaitGroup
	enabledFields      map[string]bool
	pidField           datasource.FieldAccessor
	ppidField          datasource.FieldAccessor
	cmdField           datasource.FieldAccessor
	cpuField           datasource.FieldAccessor
	memoryRSSField     datasource.FieldAccessor
	memoryVirtualField datasource.FieldAccessor
	threadCountField   datasource.FieldAccessor
	stateField         datasource.FieldAccessor
	usernameField      datasource.FieldAccessor
	startTimeField     datasource.FieldAccessor
	startTimeStrField  datasource.FieldAccessor
	mountNsIDField     datasource.FieldAccessor
	// For CPU usage calculation
	lastCPUTimes   map[int]uint64
	lastSampleTime time.Time
	// System boot time
	bootTime time.Time
}

func (p *processOperatorInstance) Name() string {
	return Name
}

func (p *processOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	// Get the system boot time
	var bootTime time.Time

	// Read /proc/stat to get the boot time
	statFile, err := os.Open("/proc/stat")
	if err == nil {
		defer statFile.Close()

		scanner := bufio.NewScanner(statFile)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					bootTimeSec, err := strconv.ParseInt(fields[1], 10, 64)
					if err == nil {
						bootTime = time.Unix(bootTimeSec, 0)
						break
					}
				}
			}
		}
	}

	if bootTime.IsZero() {
		gadgetCtx.Logger().Warn("Could not determine system boot time, using current time")
		bootTime = time.Now()
	}

	p.bootTime = bootTime

	// Start the process monitoring goroutine
	p.wg.Add(1)
	go p.monitorProcesses(gadgetCtx)

	return nil
}

func (p *processOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	close(p.done)
	p.wg.Wait()
	gadgetCtx.Logger().Debug("Process monitoring stopped")
	return nil
}

func (p *processOperatorInstance) monitorProcesses(gadgetCtx operators.GadgetContext) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			err := p.collectAndEmitProcessInfo(gadgetCtx)
			if err != nil {
				gadgetCtx.Logger().Errorf("Error collecting process info: %v", err)
			}
		}
	}
}

func (p *processOperatorInstance) collectAndEmitProcessInfo(gadgetCtx operators.GadgetContext) error {
	// Get the current time for CPU usage calculation if needed
	var timeDelta float64
	if p.enabledFields[fieldCPUUsage] {
		currentTime := time.Now()
		timeDelta = currentTime.Sub(p.lastSampleTime).Seconds()
		defer func() { p.lastSampleTime = currentTime }()
	}

	// Read /proc directory to get all processes
	procDir, err := os.Open("/proc")
	if err != nil {
		return fmt.Errorf("opening /proc directory: %w", err)
	}
	defer procDir.Close()

	// Get all process directories (named by PID)
	entries, err := procDir.Readdir(-1)
	if err != nil {
		return fmt.Errorf("reading /proc directory: %w", err)
	}

	var processes []ProcessInfo
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

		// Get process information
		procInfo, err := p.getProcessInfo(pid, timeDelta)
		if err != nil {
			// Skip processes that we can't read (they might have terminated)
			gadgetCtx.Logger().Debugf("Skipping process %d: %v", pid, err)
			continue
		}

		processes = append(processes, procInfo)
	}

	// Create a packet array to hold all processes
	packetArray, err := p.dataSource.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating packet array: %w", err)
	}
	defer func() {
		// If we exit with an error, make sure to release the packet array
		if packetArray != nil {
			p.dataSource.Release(packetArray)
		}
	}()

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

		if p.cmdField != nil {
			p.cmdField.PutString(packet, proc.Command)
		}

		if p.cpuField != nil {
			p.cpuField.PutFloat64(packet, proc.CPUUsage)
		}

		if p.memoryRSSField != nil {
			p.memoryRSSField.PutUint64(packet, proc.MemoryRSS)
		}

		if p.memoryVirtualField != nil {
			p.memoryVirtualField.PutUint64(packet, proc.MemoryVirtual)
		}

		if p.threadCountField != nil {
			p.threadCountField.PutInt32(packet, int32(proc.ThreadCount))
		}

		if p.stateField != nil {
			p.stateField.PutString(packet, proc.State)
		}

		if p.usernameField != nil {
			p.usernameField.PutUint32(packet, proc.Uid)
		}

		if p.startTimeField != nil {
			p.startTimeField.PutUint64(packet, proc.StartTime)
			p.startTimeStrField.PutString(packet, proc.StartTimeStr.Format(time.RFC3339))
		}

		// Always emit mount namespace ID
		p.mountNsIDField.PutUint64(packet, proc.MountNsID)

		// Append the packet to the array
		packetArray.Append(packet)
	}

	// Emit the packet array with all processes
	err = p.dataSource.EmitAndRelease(packetArray)
	if err != nil {
		return fmt.Errorf("emitting packet array: %w", err)
	}
	// Set to nil so it's not released again in the defer function
	packetArray = nil

	gadgetCtx.Logger().Debugf("Emitted %d process events", len(processes))
	return nil
}

// getProcessInfo reads process information from /proc/{pid}
func (p *processOperatorInstance) getProcessInfo(pid int, timeDelta float64) (ProcessInfo, error) {
	procInfo := ProcessInfo{
		PID: pid,
	}

	// Get mount namespace ID
	mntNsID, err := containerutils.GetMntNs(pid)
	if err == nil {
		procInfo.MountNsID = mntNsID
	}

	// Check which fields we need to collect
	needStatus := p.enabledFields[fieldPPID] || p.enabledFields[fieldCommand] ||
		p.enabledFields[fieldState] || p.enabledFields[fieldUid] ||
		p.enabledFields[fieldMemoryRSS] || p.enabledFields[fieldMemoryVirtual] ||
		p.enabledFields[fieldThreadCount]

	needStat := p.enabledFields[fieldCPUUsage] || p.enabledFields[fieldStartTime]

	// Read process status if needed
	if needStatus {
		statusFile := fmt.Sprintf("/proc/%d/status", pid)
		statusData, err := os.ReadFile(statusFile)
		if err != nil {
			return procInfo, fmt.Errorf("reading status file: %w", err)
		}

		// Parse status file
		scanner := bufio.NewScanner(strings.NewReader(string(statusData)))
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Name":
				if p.enabledFields[fieldCommand] {
					procInfo.Command = value
				}
			case "PPid":
				if p.enabledFields[fieldPPID] {
					ppid64, err := strconv.ParseInt(value, 10, 32)
					if err == nil {
						procInfo.PPID = int(ppid64)
					}
				}
			case "State":
				if p.enabledFields[fieldState] {
					// First character is the state code
					if len(value) > 0 {
						procInfo.State = string(value[0])
					}
				}
			case "Uid":
				if p.enabledFields[fieldUid] {
					// First UID is the real UID
					uidParts := strings.Fields(value)
					if len(uidParts) > 0 {
						// Just use the UID as is
						uid, _ := strconv.ParseUint(uidParts[0], 10, 32)
						procInfo.Uid = uint32(uid)
					}
				}
			case "VmSize":
				if p.enabledFields[fieldMemoryVirtual] {
					// Format: "123456 kB"
					vmSizeParts := strings.Fields(value)
					if len(vmSizeParts) > 0 {
						vmSize, err := strconv.ParseUint(vmSizeParts[0], 10, 64)
						if err == nil {
							// Convert from kB to bytes
							procInfo.MemoryVirtual = vmSize * 1024
						}
					}
				}
			case "VmRSS":
				if p.enabledFields[fieldMemoryRSS] {
					// Format: "123456 kB"
					vmRSSParts := strings.Fields(value)
					if len(vmRSSParts) > 0 {
						vmRSS, err := strconv.ParseUint(vmRSSParts[0], 10, 64)
						if err == nil {
							// Convert from kB to bytes
							procInfo.MemoryRSS = vmRSS * 1024
						}
					}
				}
			case "Threads":
				if p.enabledFields[fieldThreadCount] {
					threads64, err := strconv.ParseInt(value, 10, 32)
					if err == nil {
						procInfo.ThreadCount = int(threads64)
					}
				}
			}
		}
	}

	// Read process stat for CPU usage and start time if needed
	if needStat {
		statFile := fmt.Sprintf("/proc/%d/stat", pid)
		statData, err := os.ReadFile(statFile)
		if err != nil {
			return procInfo, fmt.Errorf("reading stat file: %w", err)
		}

		// Parse stat file
		statFields := strings.Fields(string(statData))
		if len(statFields) >= 22 {
			// Calculate CPU usage if needed
			if p.enabledFields[fieldCPUUsage] {
				// Field 14 (utime) and 15 (stime) are the user and system CPU time
				utime, err1 := strconv.ParseUint(statFields[13], 10, 64)
				stime, err2 := strconv.ParseUint(statFields[14], 10, 64)
				if err1 == nil && err2 == nil {
					totalTime := utime + stime

					// Calculate CPU usage percentage
					if prevTime, ok := p.lastCPUTimes[pid]; ok && timeDelta > 0 {
						// CPU usage is the difference in CPU time divided by the elapsed time
						cpuUsage := float64(totalTime-prevTime) / timeDelta * 100.0
						procInfo.CPUUsage = cpuUsage
					} else {
						procInfo.CPUUsage = 0.0
					}

					// Store current CPU time for next calculation
					p.lastCPUTimes[pid] = totalTime
				}
			}

			// Get start time if needed
			if p.enabledFields[fieldStartTime] {
				// Field 22 is the start time (in clock ticks since system boot)
				if startTime, err := strconv.ParseUint(statFields[21], 10, 64); err == nil {
					procInfo.StartTime = startTime

					// Convert clock ticks to seconds since boot
					startTimeSec := float64(startTime) / clockTicksPerSecond

					// Calculate the actual start time by adding to boot time
					procInfo.StartTimeStr = p.bootTime.Add(time.Duration(startTimeSec * float64(time.Second)))
				}
			}
		}
	}

	return procInfo, nil
}

// Operator is the global instance of the process operator
var Operator = &processOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}

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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
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
	fieldCommand       = "comm"
	fieldCPUUsage      = "cpuUsage"
	fieldMemoryRSS     = "memoryRSS"
	fieldMemoryVirtual = "memoryVirtual"
	fieldThreadCount   = "threadCount"
	fieldState         = "state"
	fieldUid           = "uid"
	fieldStartTime     = "startTime_raw"
	fieldStartTimeStr  = "startTime"
	fieldMountNsID     = "mountnsid"

	// Clock ticks per second (typically 100 on most Linux systems)
	// This could be determined dynamically using sysconf(_SC_CLK_TCK) in C
	// or by reading /proc/stat and calculating based on uptime
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
		gadgetCtx.Logger().Debug("No fields specified for internal datasource 'processes', enabling all fields")
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

		gadgetCtx.Logger().Debugf("Enabled fields for internal datasource 'processes': %v", fields)
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
		instance.cpuField, err = ds.AddField(fieldCPUUsage, api.Kind_Float64, datasource.WithAnnotations(map[string]string{
			"columns.precision": "1",
			"columns.alignment": "right",
		}))
		if err != nil {
			return nil, fmt.Errorf("adding cpuUsage field: %w", err)
		}
	}

	if instance.enabledFields[fieldMemoryRSS] {
		instance.memoryRSSField, err = ds.AddField(fieldMemoryRSS, api.Kind_Uint64, datasource.WithAnnotations(map[string]string{
			"columns.alignment": "right",
		}))
		if err != nil {
			return nil, fmt.Errorf("adding memoryRSS field: %w", err)
		}
	}

	if instance.enabledFields[fieldMemoryVirtual] {
		instance.memoryVirtualField, err = ds.AddField(fieldMemoryVirtual, api.Kind_Uint64, datasource.WithAnnotations(map[string]string{
			"columns.alignment": "right",
		}))
		if err != nil {
			return nil, fmt.Errorf("adding memoryVirtual field: %w", err)
		}
	}

	if instance.enabledFields[fieldThreadCount] {
		instance.threadCountField, err = ds.AddField(fieldThreadCount, api.Kind_Int32, datasource.WithAnnotations(map[string]string{
			"columns.alignment": "right",
		}))
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
		instance.uidField, err = ds.AddField(fieldUid, api.Kind_Uint32)
		if err != nil {
			return nil, fmt.Errorf("adding uid field: %w", err)
		}
	}

	if instance.enabledFields[fieldStartTime] {
		instance.startTimeField, err = ds.AddField(fieldStartTime, api.Kind_Uint64, datasource.WithTags("type:gadget_timestamp"))
		if err != nil {
			return nil, fmt.Errorf("adding startTime_raw field: %w", err)
		}

		// Add the formatted start time field
		instance.startTimeStrField, err = ds.AddField(fieldStartTimeStr, api.Kind_String)
		if err != nil {
			return nil, fmt.Errorf("adding startTime field: %w", err)
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

	// Precalculate which files we need to read
	instance.needStatus = instance.enabledFields[fieldPPID] || instance.enabledFields[fieldCommand] ||
		instance.enabledFields[fieldState] || instance.enabledFields[fieldUid] ||
		instance.enabledFields[fieldMemoryRSS] || instance.enabledFields[fieldMemoryVirtual] ||
		instance.enabledFields[fieldThreadCount]

	instance.needStat = instance.enabledFields[fieldCPUUsage] || instance.enabledFields[fieldStartTime]

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
	uidField           datasource.FieldAccessor
	startTimeField     datasource.FieldAccessor
	startTimeStrField  datasource.FieldAccessor
	mountNsIDField     datasource.FieldAccessor
	// Precalculated flags for which files to read
	needStatus bool
	needStat   bool
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

	bootTime = getBootTime(gadgetCtx)

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

func getBootTime(gadgetCtx operators.GadgetContext) time.Time {
	// Read /proc/stat to get the boot time
	statFile, err := os.Open(filepath.Join(host.HostProcFs, "stat"))
	if err != nil {
		gadgetCtx.Logger().Warn("Could not open /proc/stat, using current time")
		return time.Now()
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
		return time.Unix(bootTimeSec, 0)
	}

	gadgetCtx.Logger().Warn("Could not determine system boot time, using current time")
	return time.Now()
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
	if p.cpuField != nil {
		currentTime := time.Now()
		timeDelta = currentTime.Sub(p.lastSampleTime).Seconds()
		defer func() { p.lastSampleTime = currentTime }()
	}

	// Read /proc directory to get all processes
	entries, err := os.ReadDir(host.HostProcFs)
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

		if p.uidField != nil {
			p.uidField.PutUint32(packet, proc.Uid)
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

	return nil
}

// getProcessInfo reads process information from /proc/{pid}
func (p *processOperatorInstance) getProcessInfo(pid int, timeDelta float64) (ProcessInfo, error) {
	procInfo := ProcessInfo{
		PID: pid,
	}

	// Get mount namespace ID
	procInfo.MountNsID, _ = containerutils.GetMntNs(pid)

	// Read process status if needed
	if p.needStatus {
		statusFile := filepath.Join(host.HostProcFs, fmt.Sprint(pid), "status")
		statusData, err := os.ReadFile(statusFile)
		if err != nil {
			return procInfo, fmt.Errorf("reading status file for PID %d: %w", pid, err)
		}
		if len(statusData) == 0 {
			return procInfo, fmt.Errorf("empty status file for PID %d", pid)
		}

		// Parse status file - work directly with bytes to avoid string conversions
		scanner := bufio.NewScanner(bytes.NewReader(statusData))
		for scanner.Scan() {
			line := scanner.Bytes()
			idx := bytes.Index(line, []byte(":\t"))
			if idx == -1 {
				continue
			}

			key := string(line[:idx])
			value := string(line[idx+2:])

			switch key {
			case "Name":
				if p.cmdField != nil {
					procInfo.Command = unescapeCommand(value)
				}
			case "PPid":
				if p.ppidField != nil {
					ppid64, err := strconv.ParseInt(value, 10, 32)
					if err == nil {
						procInfo.PPID = int(ppid64)
					}
				}
			case "State":
				if p.stateField != nil {
					// First character is the state code
					if len(value) > 0 {
						procInfo.State = string(value[0])
					}
				}
			case "Uid":
				if p.uidField != nil {
					// First UID is the real UID
					uidParts := strings.Fields(value)
					if len(uidParts) > 0 {
						// Just use the UID as is
						uid, _ := strconv.ParseUint(uidParts[0], 10, 32)
						procInfo.Uid = uint32(uid)
					}
				}
			case "VmSize":
				if p.memoryVirtualField != nil {
					// Format: "123456 kB"
					vmSizeParts := strings.Fields(value)
					if len(vmSizeParts) > 0 {
						vmSize, err := strconv.ParseUint(vmSizeParts[0], 10, 64)
						if err != nil {
							// Skip this field if parsing fails
							continue
						}
						// Convert from kB to bytes
						procInfo.MemoryVirtual = vmSize * 1024
					}
				}
			case "VmRSS":
				if p.memoryRSSField != nil {
					// Format: "123456 kB"
					vmRSSParts := strings.Fields(value)
					if len(vmRSSParts) > 0 {
						vmRSS, err := strconv.ParseUint(vmRSSParts[0], 10, 64)
						if err != nil {
							// Skip this field if parsing fails
							continue
						}
						// Convert from kB to bytes
						procInfo.MemoryRSS = vmRSS * 1024
					}
				}
			case "Threads":
				if p.threadCountField != nil {
					threads64, err := strconv.ParseInt(value, 10, 32)
					if err != nil {
						// Skip this field if parsing fails
						continue
					}
					procInfo.ThreadCount = int(threads64)
				}
			}
		}

		// Check for scanner errors
		if err := scanner.Err(); err != nil {
			return procInfo, fmt.Errorf("scanning status file for PID %d: %w", pid, err)
		}
	}

	// Read process stat for CPU usage and start time if needed
	if p.needStat {
		statFile := filepath.Join(host.HostProcFs, fmt.Sprintf("%d/stat", pid))
		statData, err := os.ReadFile(statFile)
		if err != nil {
			return procInfo, fmt.Errorf("reading stat file for PID %d: %w", pid, err)
		}
		if len(statData) == 0 {
			return procInfo, fmt.Errorf("empty stat file for PID %d", pid)
		}

		statFields := make([][]byte, 22)

		// Parse stat file - we need to handle the comm field specially
		// The comm field is enclosed in parentheses and may contain spaces
		err = parseStatFile(statData, statFields)
		if err != nil {
			return procInfo, fmt.Errorf("parsing stat file: %w", err)
		}

		// Calculate CPU usage if needed
		if p.cpuField != nil {
			// Field 14 (utime) and 15 (stime) are the user and system CPU time
			utime, err1 := strconv.ParseUint(string(statFields[13]), 10, 64)
			stime, err2 := strconv.ParseUint(string(statFields[14]), 10, 64)
			if err1 == nil && err2 == nil {
				totalTime := utime + stime

				// Calculate CPU usage percentage
				if prevTime, ok := p.lastCPUTimes[pid]; ok && timeDelta > 0 {
					// CPU usage is the difference in CPU time (in jiffies) divided by the elapsed time (in seconds)
					// We need to convert jiffies to seconds by dividing by clockTicksPerSecond
					cpuTimeDiff := float64(totalTime - prevTime)
					if cpuTimeDiff < 0 {
						// Handle case where process was restarted with same PID
						cpuTimeDiff = float64(totalTime)
					}
					procInfo.CPUUsage = (cpuTimeDiff / clockTicksPerSecond / timeDelta) * 100.0
				}

				// Store current CPU time for next calculation
				p.lastCPUTimes[pid] = totalTime
			}
		}

		// Get start time if needed
		if p.startTimeField != nil {
			// Field 22 is the start time (in clock ticks since system boot)
			if startTime, err := strconv.ParseUint(string(statFields[21]), 10, 64); err == nil {
				procInfo.StartTime = startTime

				// Convert clock ticks to seconds since boot
				startTimeSec := float64(startTime) / clockTicksPerSecond

				// Calculate the actual start time by adding to boot time
				procInfo.StartTimeStr = p.bootTime.Add(time.Duration(startTimeSec * float64(time.Second)))
			}
		}
	}

	return procInfo, nil
}

// unescapeCommand unescapes the command string according to kernel escaping rules
// %ESCAPE_SPACE: ('\f', '\n', '\r', '\t', '\v')
// %ESCAPE_SPECIAL: ('\"', '\\', '\a', '\e')
func unescapeCommand(cmd string) string {
	// If there are no escape sequences, return the original string
	if !strings.Contains(cmd, "\\") {
		return cmd
	}

	var builder strings.Builder
	builder.Grow(len(cmd)) // Pre-allocate capacity to avoid reallocations

	for i := 0; i < len(cmd); i++ {
		// Check for escape sequence
		if cmd[i] == '\\' && i+1 < len(cmd) {
			switch cmd[i+1] {
			// Special whitespace characters
			case 'f':
				builder.WriteByte('\f')
			case 'n':
				builder.WriteByte('\n')
			case 'r':
				builder.WriteByte('\r')
			case 't':
				builder.WriteByte('\t')
			case 'v':
				builder.WriteByte('\v')
			// Special characters
			case '"':
				builder.WriteByte('"')
			case '\\':
				builder.WriteByte('\\')
			case 'a':
				builder.WriteByte('\a')
			case 'e':
				builder.WriteByte(27) // ASCII 27 for escape character
			default:
				// Unknown escape sequence, keep both characters
				builder.WriteByte('\\')
				builder.WriteByte(cmd[i+1])
			}
			i++ // Skip the next character as we've already processed it
		} else {
			builder.WriteByte(cmd[i])
		}
	}

	return builder.String()
}

// parseStatFile parses the /proc/[pid]/stat file, handling the comm field correctly
// The comm field is enclosed in parentheses and may contain spaces
func parseStatFile(statData []byte, result [][]byte) error {
	// The format of /proc/[pid]/stat is:
	// pid (comm) state ppid ... and more fields
	// The challenge is that comm can contain spaces and parentheses

	// First, find the closing parenthesis for the comm field
	commEndIdx := bytes.LastIndex(statData, []byte{')'})
	if commEndIdx == -1 {
		return fmt.Errorf("invalid stat file format: missing closing parenthesis")
	}

	// Find the opening parenthesis
	commStartIdx := bytes.Index(statData, []byte{'('})
	if commStartIdx == -1 {
		return fmt.Errorf("invalid stat file format: missing opening parenthesis")
	}

	// Validate that the opening parenthesis comes before the closing one
	if commStartIdx >= commEndIdx {
		return fmt.Errorf("invalid stat file format: parentheses in wrong order")
	}

	// Extract the pid (field 1)
	pidStr := bytes.TrimSpace(statData[:commStartIdx])

	// Extract the comm (field 2)
	comm := statData[commStartIdx+1 : commEndIdx]

	// Extract the rest of the fields
	// We only need a few specific fields, so we'll parse them directly
	// without creating a full array of all fields
	restData := statData[commEndIdx+1:]
	fields := bytes.Fields(restData)

	// We need at least 21 fields after the comm field to access field 22
	if len(fields) < 21 {
		return fmt.Errorf("invalid stat file format: not enough fields")
	}

	result[0] = pidStr      // Field 1 (pid)
	result[1] = comm        // Field 2 (comm)
	result[13] = fields[11] // Field 14 (utime)
	result[14] = fields[12] // Field 15 (stime)
	result[21] = fields[19] // Field 22 (starttime)

	return nil
}

// Operator is the global instance of the process operator
var Operator = &processOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}

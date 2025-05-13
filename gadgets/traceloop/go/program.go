// Copyright 2025 The Inspektor Gadget authors
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
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

type eventType uint32

const (
	syscallEventTypeEnter eventType = 0
	syscallEventTypeExit            = 1
	syscallEventTypeCont            = 2
)

// These consts must match the content of program.bpf.c.
const (
	useNullByteLength        uint64 = 0x0fffffffffffffff
	useRetAsParamLength      uint64 = 0x0ffffffffffffffe
	useArgIndexAsParamLength uint64 = 0x0ffffffffffffff0
	paramProbeAtExitMask     uint64 = 0xf000000000000000

	syscallArgs uint8 = 6

	// os.Getpagesize() in wasm will return 65536:
	// https://cs.opensource.google/go/go/+/master:src/runtime/os_wasm.go;l=13-14?q=physPageSize&ss=go%2Fgo&start=11
	// https://webassembly.github.io/spec/core/exec/runtime.html#memory-instances
	linuxPageSize uint32 = 4096

	// the max entries of the syscall_filters map
	maxSyscallFilters int = 16
)

// TODO Find all syscalls which take a char * as argument and add them there.
var syscallDefs = map[string][6]uint64{
	"execve":      {useNullByteLength, 0, 0, 0, 0, 0},
	"access":      {useNullByteLength, 0, 0, 0, 0, 0},
	"open":        {useNullByteLength, 0, 0, 0, 0, 0},
	"openat":      {0, useNullByteLength, 0, 0, 0, 0},
	"mkdir":       {useNullByteLength, 0, 0, 0, 0, 0},
	"chdir":       {useNullByteLength, 0, 0, 0, 0, 0},
	"pivot_root":  {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"mount":       {useNullByteLength, useNullByteLength, useNullByteLength, 0, 0, 0},
	"umount2":     {useNullByteLength, 0, 0, 0, 0, 0},
	"sethostname": {useNullByteLength, 0, 0, 0, 0, 0},
	"statfs":      {useNullByteLength, 0, 0, 0, 0, 0},
	"stat":        {useNullByteLength, 0, 0, 0, 0, 0},
	"statx":       {0, useNullByteLength, 0, 0, 0, 0},
	"lstat":       {useNullByteLength, 0, 0, 0, 0, 0},
	"fgetxattr":   {0, useNullByteLength, 0, 0, 0, 0},
	"lgetxattr":   {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"getxattr":    {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"newfstatat":  {0, useNullByteLength, 0, 0, 0, 0},
	"read":        {0, useRetAsParamLength | paramProbeAtExitMask, 0, 0, 0, 0},
	"write":       {0, useArgIndexAsParamLength + 2, 0, 0, 0, 0},
	"getcwd":      {useNullByteLength | paramProbeAtExitMask, 0, 0, 0, 0, 0},
	"pread64":     {0, useRetAsParamLength | paramProbeAtExitMask, 0, 0, 0, 0},
}

// Used as cache for getSyscallDeclaration().
var sysDeclarationCache map[string]api.SyscallDeclaration

type eventFields struct {
	mntnsID    api.Field
	cpu        api.Field
	pid        api.Field
	comm       api.Field
	syscall    api.Field
	parameters api.Field
	ret        api.Field
}

var (
	dsOutput api.DataSource
	fields   eventFields
)

type containerRingReader struct {
	innerBuffer api.Map
	perfReader  api.PerfReader
}

type tracelooper struct {
	mapOfPerfBuffers api.Map

	// key:   mntnsID
	// value: *containerRingReader
	readers sync.Map
}

var t tracelooper

// Keep in sync with type in program.bpf.c.
type traceloopSyscallEventContT struct {
	EventType          eventType
	Param              [128]uint8
	MonotonicTimestamp uint64
	Length             uint64
	Index              uint8
	Failed             uint8
	_                  [5]byte
}

// Keep in sync with type in program.bpf.c.
type traceloopSyscallEventT struct {
	EventType          eventType
	Args               [6]uint64
	MonotonicTimestamp uint64
	BootTimestamp      uint64
	Pid                uint32
	Cpu                uint16
	Id                 uint16
	Comm               [16]uint8
	ContNr             uint8
	_                  [62]byte
}

type syscallEvent struct {
	bootTimestamp      uint64
	monotonicTimestamp uint64
	typ                eventType
	contNr             uint8
	cpu                uint16
	id                 uint16
	pid                uint32
	comm               string
	args               []uint64
	mountNsID          uint64
	retval             uint64
}

type syscallEventContinued struct {
	monotonicTimestamp uint64
	index              uint8
	param              string
}

type syscallParam struct {
	name    string
	value   string
	content *string
}

type event struct {
	timestamp  int64
	mountNsID  uint64
	cpu        uint16
	pid        uint32
	comm       string
	syscall    string
	parameters []syscallParam
	retval     string
}

func paramsToString(parameters []syscallParam) string {
	var sb strings.Builder

	for idx, p := range parameters {
		value := p.value
		if p.content != nil {
			value = *p.content
		}

		fmt.Fprintf(&sb, "%s=%s", p.name, value)

		if idx < len(parameters)-1 {
			sb.WriteString(", ")
		}
	}

	return sb.String()
}

func (t *tracelooper) attach(mntnsID uint64) error {
	perfBufferName := fmt.Sprintf("perf_buffer_%d", mntnsID)

	// 1. Create inner Map as perf buffer.
	// Keep the spec in sync with program.bpf.c.
	innerBuffer, err := api.NewMap(api.MapSpec{
		Name:      perfBufferName,
		Type:      api.PerfEventArray,
		KeySize:   uint32(4),
		ValueSize: uint32(4),
	})
	if err != nil {
		return fmt.Errorf("creating map %s", fmt.Sprintf("perf_buffer_%d", mntnsID))
	}

	// 2. Use this inner Map to create the perf reader.
	perfReader, err := api.NewPerfReader(innerBuffer, 64*linuxPageSize, true)
	if err != nil {
		innerBuffer.Close()

		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	// 3. Add the inner map's file descriptor to outer map.
	err = t.mapOfPerfBuffers.Update(mntnsID, innerBuffer, api.UpdateNoExist)
	if err != nil {
		innerBuffer.Close()
		perfReader.Close()

		return fmt.Errorf("adding perf buffer to map with mntnsID %d: %w", mntnsID, err)
	}

	t.readers.Store(mntnsID, &containerRingReader{
		innerBuffer: innerBuffer,
		perfReader:  perfReader,
	})

	return nil
}

func (t *tracelooper) detach(mntnsID uint64) error {
	err := t.mapOfPerfBuffers.Delete(mntnsID)
	if err != nil {
		return fmt.Errorf("removing perf buffer from map with mntnsID %d: %w", mntnsID, err)
	}

	return nil
}

func fromCString(in []byte) string {
	idx := bytes.IndexByte(in, 0)
	switch {
	case idx == -1:
		return string(in)
	case idx < len(in):
		return string(in[:idx])
	default:
		return string(in)
	}
}

func fromCStringN(in []byte, length int) string {
	l := len(in)
	if length < l {
		l = length
	}

	buf := in[:l]
	idx := bytes.IndexByte(buf, 0)
	switch {
	case idx == -1:
		return string(in)
	case idx < l:
		return string(in[:idx])
	default:
		return string(in)
	}
}

func timestampFromEvent(event *syscallEvent) int64 {
	return time.Unix(0, int64(event.bootTimestamp)).Add(0).UnixNano()
}

// Copied/pasted/adapted from kernel macro round_up:
// https://elixir.bootlin.com/linux/v6.0/source/include/linux/math.h#L25
func roundUp(x, y uintptr) uintptr {
	return ((x - 1) | (y - 1)) + 1
}

// The kernel aligns size of perf event with the following snippet:
// void perf_prepare_sample(...)
//
//	{
//		//...
//		size = round_up(sum + sizeof(u32), sizeof(u64));
//		raw->size = size - sizeof(u32);
//		frag->pad = raw->size - sum;
//		// ...
//	}
//
// (https://elixir.bootlin.com/linux/v6.0/source/kernel/events/core.c#L7353)
// In the case of our structure of interest (i.e. struct_syscall_event_t and
// struct_syscall_event_cont_t), their size will be increased by 4, here is
// an example for struct_syscall_event_t which size is 88:
// size = round_up(sum + sizeof(u32), sizeof(u64))
//
//	= round_up(88 + 4, 8)
//	= round_up(92, 8)
//	= 96
//
// raw->size = size - sizeof(u32)
//
//	= 96 - 4
//	= 92
//
// So, 4 bytes will be added as padding at the end of the event and the size we
// will read getting perfEventSample will be 92 instead of 88.
func alignSize(structSize uintptr) uintptr {
	var ret uintptr
	var foo uint64
	var bar uint32

	ret = roundUp(structSize+unsafe.Sizeof(bar), unsafe.Sizeof(foo))
	ret = ret - unsafe.Sizeof(bar)

	return ret
}

// Convert a return value to corresponding error number if meaningful.
// See man syscalls:
// Note:
// system calls indicate a failure by returning a negative error
// number to the caller on architectures without a separate error
// register/flag, as noted in syscall(2); when this happens, the
// wrapper function negates the returned error number (to make it
// positive), copies it to errno, and returns -1 to the caller of
// the wrapper.
func retToStr(ret uint64) string {
	errNo := int64(ret)
	if errNo >= -4095 && errNo <= -1 {
		return fmt.Sprintf("-1 (%s)", syscall.Errno(-errNo).Error())
	}
	return fmt.Sprintf("%d", ret)
}

func getSyscallDeclaration(name string) (api.SyscallDeclaration, error) {
	if sysDeclarationCache == nil {
		sysDeclarationCache = make(map[string]api.SyscallDeclaration)
	}

	if declaration, ok := sysDeclarationCache[name]; ok {
		return declaration, nil
	}

	declaration, err := api.GetSyscallDeclaration(name)
	if err != nil {
		return api.SyscallDeclaration{}, fmt.Errorf("getting syscall definition: %w", err)
	}

	sysDeclarationCache[name] = declaration

	return declaration, nil
}

func (t *tracelooper) read(mntnsID uint64, reader *containerRingReader) ([]*event, error) {
	syscallContinuedEventsMap := make(map[uint64][]*syscallEventContinued)
	syscallEnterEventsMap := make(map[uint64][]*syscallEvent)
	syscallExitEventsMap := make(map[uint64][]*syscallEvent)
	var sysEventCont *traceloopSyscallEventContT
	events := make([]*event, 0)
	var sysEvent *traceloopSyscallEventT

	err := reader.perfReader.Pause()
	if err != nil {
		return nil, err
	}

	sysEventSize := alignSize(unsafe.Sizeof(*sysEvent))
	for {
		record := make([]byte, sysEventSize)
		if err := reader.perfReader.Read(record); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			} else {
				return nil, err
			}
		}

		sysEvent = (*traceloopSyscallEventT)(unsafe.Pointer(&record[0]))

		switch sysEvent.EventType {
		case syscallEventTypeEnter, syscallEventTypeExit:

			event := &syscallEvent{
				bootTimestamp:      sysEvent.BootTimestamp,
				monotonicTimestamp: sysEvent.MonotonicTimestamp,
				typ:                sysEvent.EventType,
				contNr:             sysEvent.ContNr,
				cpu:                sysEvent.Cpu,
				id:                 sysEvent.Id,
				pid:                sysEvent.Pid,
				comm:               fromCString(sysEvent.Comm[:]),
				mountNsID:          mntnsID,
			}

			var typeMap *map[uint64][]*syscallEvent
			switch event.typ {
			case syscallEventTypeEnter:
				event.args = make([]uint64, syscallArgs)
				for i := uint8(0); i < syscallArgs; i++ {
					event.args[i] = sysEvent.Args[i]
				}

				typeMap = &syscallEnterEventsMap
			case syscallEventTypeExit:
				event.retval = sysEvent.Args[0]

				typeMap = &syscallExitEventsMap
			}

			(*typeMap)[event.monotonicTimestamp] = append((*typeMap)[event.monotonicTimestamp], event)
		case syscallEventTypeCont:
			sysEventCont = (*traceloopSyscallEventContT)(unsafe.Pointer(&record[0]))

			event := &syscallEventContinued{
				monotonicTimestamp: sysEventCont.MonotonicTimestamp,
				index:              sysEventCont.Index,
			}

			if sysEventCont.Failed != 0 {
				event.param = "(Failed to dereference pointer)"
			} else if sysEventCont.Length == useNullByteLength {
				// 0 byte at [C.PARAM_LENGTH - 1] is enforced in BPF code
				event.param = fromCString(sysEventCont.Param[:])
			} else {
				event.param = fromCStringN(sysEventCont.Param[:], int(sysEventCont.Length))
			}

			// Remove all non unicode character from the string.
			event.param = strconv.Quote(event.param)

			syscallContinuedEventsMap[event.monotonicTimestamp] = append(syscallContinuedEventsMap[event.monotonicTimestamp], event)
		default:
			api.Debugf("unknown event type: got %d, expected %d or %d", sysEvent.EventType, syscallEventTypeEnter, syscallEventTypeCont)
		}
	}

	err = reader.perfReader.Resume()
	if err != nil {
		return nil, err
	}

	// Publish the events we gathered.
	for enterTimestamp, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			event := &event{
				timestamp: timestampFromEvent(enterEvent),
				mountNsID: enterEvent.mountNsID,
				cpu:       enterEvent.cpu,
				pid:       enterEvent.pid,
				comm:      enterEvent.comm,
				syscall:   syscallName,
			}

			syscallDeclaration, err := getSyscallDeclaration(event.syscall)
			if err != nil {
				return nil, fmt.Errorf("getting syscall definition: %w", err)
			}

			parametersNumber := len(syscallDeclaration.Params)
			event.parameters = make([]syscallParam, parametersNumber)
			api.Debugf("\tevent parametersNumber: %d", parametersNumber)

			for i := 0; i < parametersNumber; i++ {
				paramName := syscallDeclaration.Params[i].Name
				api.Debugf("\t\tevent paramName: %q", paramName)

				isPointer := syscallDeclaration.Params[i].IsPointer

				format := "%d"
				if isPointer {
					format = "0x%x"
				}
				paramValue := fmt.Sprintf(format, enterEvent.args[i])
				api.Debugf("\t\tevent paramValue: %q", paramValue)

				var paramContent *string

				for _, syscallContEvent := range syscallContinuedEventsMap[enterTimestamp] {
					if syscallContEvent.index == uint8(i) {
						paramContent = &syscallContEvent.param
						api.Debugf("\t\t\tevent paramContent: %q", *paramContent)

						break
					}
				}

				event.parameters[i] = syscallParam{
					name:    paramName,
					value:   paramValue,
					content: paramContent,
				}
			}

			delete(syscallContinuedEventsMap, enterTimestamp)

			// There is no exit event for exit(), exit_group() and rt_sigreturn().
			if event.syscall == "exit" || event.syscall == "exit_group" || event.syscall == "rt_sigreturn" {
				delete(syscallEnterEventsMap, enterTimestamp)

				// As there is no exit events for these syscalls,
				// then there is no return value.
				event.retval = "X"

				api.Debugf("%v", event)
				events = append(events, event)

				continue
			}

			exitTimestampEvents, ok := syscallExitEventsMap[enterTimestamp]
			if !ok {
				api.Debugf("no exit event for timestamp %d", enterTimestamp)

				continue
			}

			for _, exitEvent := range exitTimestampEvents {
				if enterEvent.id != exitEvent.id || enterEvent.pid != exitEvent.pid {
					continue
				}

				event.retval = retToStr(exitEvent.retval)

				delete(syscallEnterEventsMap, enterTimestamp)
				delete(syscallExitEventsMap, enterTimestamp)

				api.Debugf("%v", event)
				events = append(events, event)

				break
			}
		}
	}

	api.Debugf("len(events): %d; len(syscallEnterEventsMap): %d; len(syscallExitEventsMap): %d; len(syscallContinuedEventsMap): %d\n", len(events), len(syscallEnterEventsMap), len(syscallExitEventsMap), len(syscallContinuedEventsMap))

	// It is possible there are some incomplete events for several reasons:
	// 1. Traceloop was started in the middle of a syscall, then we will only get
	//    the exit but not the enter.
	// 2. Traceloop was stopped in the middle of a syscall, then we will only get
	//    the enter but not the exit
	// 3. The buffer is full and so it only remains some exit events and not the
	//    corresponding enter.
	// Rather than dropping these incomplete events, we just add them to the
	// events to be published.
	for _, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteEnterEvent := &event{
				timestamp: timestampFromEvent(enterEvent),
				mountNsID: enterEvent.mountNsID,
				cpu:       enterEvent.cpu,
				pid:       enterEvent.pid,
				comm:      enterEvent.comm,
				syscall:   syscallName,
				retval:    "unfinished",
			}

			events = append(events, incompleteEnterEvent)

			api.Debugf("enterEvent(%q): %v\n", syscallName, enterEvent)
		}
	}

	for _, exitTimestampEvents := range syscallExitEventsMap {
		for _, exitEvent := range exitTimestampEvents {
			syscallName, err := api.GetSyscallName(exitEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteExitEvent := &event{
				timestamp: timestampFromEvent(exitEvent),
				cpu:       exitEvent.cpu,
				pid:       exitEvent.pid,
				comm:      exitEvent.comm,
				mountNsID: exitEvent.mountNsID,
				syscall:   syscallName,
				retval:    retToStr(exitEvent.retval),
			}

			events = append(events, incompleteExitEvent)

			api.Debugf("exitEvent(%q): %v\n", syscallName, exitEvent)
		}
	}

	// Sort all events by ascending timestamp.
	sort.Slice(events, func(i, j int) bool {
		return events[i].timestamp < events[j].timestamp
	})

	return events, nil
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var sysEventCont *traceloopSyscallEventContT
	var sysEvent *traceloopSyscallEventT
	var err error
	sysEventSize := alignSize(unsafe.Sizeof(*sysEvent))
	sysEventContSize := alignSize(unsafe.Sizeof(*sysEventCont))

	if sysEventSize != sysEventContSize {
		api.Errorf("event sizes must be the same, there is a mismatch: %d != %d", sysEventSize, sysEventContSize)
		return 1
	}

	dsOutput, err = api.NewDataSource("traceloop", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %v", err)
		return 1
	}

	fieldsInfo := []struct {
		name  string
		kind  api.FieldKind
		field *api.Field
	}{
		{
			name:  "mntns_id",
			kind:  api.Kind_Uint64,
			field: &fields.mntnsID,
		},
		{
			name:  "cpu",
			kind:  api.Kind_Uint16,
			field: &fields.cpu,
		},
		{
			name:  "pid",
			kind:  api.Kind_Uint32,
			field: &fields.pid,
		},
		{
			name:  "comm",
			kind:  api.Kind_String,
			field: &fields.comm,
		},
		{
			name:  "syscall",
			kind:  api.Kind_String,
			field: &fields.syscall,
		},
		{
			name:  "parameters",
			kind:  api.Kind_String,
			field: &fields.parameters,
		},
		{
			name:  "ret",
			kind:  api.Kind_String,
			field: &fields.ret,
		},
	}
	for _, fieldInfo := range fieldsInfo {
		name := fieldInfo.name
		*fieldInfo.field, err = dsOutput.AddField(name, fieldInfo.kind)
		if err != nil {
			api.Errorf("adding %s field: %v", name, err)
			return 1
		}
	}

	err = fields.mntnsID.AddTag("type:gadget_mntns_id")
	if err != nil {
		api.Errorf("adding tag to mntns_id field: %v", err)
		return 1
	}

	return 0
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {

	rawString, err := api.GetParamValue("syscall-filters", 256)
	if err != nil {
		api.Errorf("failed to get param: %v", err)
		return 1
	}

	syscallsFilterMapName := "syscall_filters"
	syscallsFilterMap, err := api.GetMap(syscallsFilterMapName)
	if err != nil {
		api.Errorf("no map named %s", syscallsFilterMapName)
		return 1
	}

	var syscallFilters []string

	if rawString != "" {
		syscallFilters = strings.Split(rawString, ",")
	}

	// Try to keep the max entries in syscall_filters in sync with user code and
	// ebpf code.
	if len(syscallFilters) > maxSyscallFilters {
		api.Errorf("Length of --syscall-filters exceeded. No more than 16 values can be added.")
		return 1
	}
	for _, name := range syscallFilters {
		id, err := api.GetSyscallID(name)
		if err != nil {
			api.Errorf("syscall %q does not exist", name)
			return 1
		}

		err = syscallsFilterMap.Put(uint64(id), true)
		if err != nil {
			api.Errorf("Could not add %q (%d) to syscall filter map: %v", name, id, err)
			return 1
		}
	}
	
	if len(syscallFilters) > 0 {
		syscallsEnableFilterMapName := "syscall_enable_filters"
		syscallsEnableFilterMap, err := api.GetMap(syscallsEnableFilterMapName)
		if err != nil {
			api.Errorf("no map named %s", syscallsEnableFilterMapName)
			return 1
		}
		err = syscallsEnableFilterMap.Put(uint32(0), true)
		if err != nil {
			api.Errorf("Could not add not enable filter syscall: %v", err)
			return 1
		}
	}

	mapName := "map_of_perf_buffers"

	t.mapOfPerfBuffers, err = api.GetMap(mapName)
	if err != nil {
		api.Errorf("no map named %s", mapName)
		return 1
	}

	syscallsMapName := "syscalls"

	syscallsMap, err := api.GetMap(syscallsMapName)
	if err != nil {
		api.Errorf("no map named %s", syscallsMapName)
		return 1
	}

	// Fill the syscall map with specific syscall signatures.
	for name, def := range syscallDefs {
		id, err := api.GetSyscallID(name)
		if err != nil {
			// It's possible that the syscall doesn't exist for this architecture, skip it
			continue
		}

		err = syscallsMap.Put(uint64(id), def)
		if err != nil {
			api.Errorf("storing %s definition in corresponding map: %v", name, err)
			return 1
		}
	}

	ds, err := api.GetDataSource("containers")
	if err != nil {
		api.Errorf("Failed to get data source: %v", err)
		return 1
	}

	eventTypeField, err := ds.GetField("event_type")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	mntnsIDField, err := ds.GetField("mntns_id")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	nameField, err := ds.GetField("name")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	ds.Subscribe(func(ds api.DataSource, data api.Data) {
		// Event type is CREATED or DELETED, 7 is the length of longest string, i.e.
		// DELETED.
		eventType, err := eventTypeField.String(data, 7)
		if err != nil {
			api.Errorf("getting event_type from corresponding field: %v", err)
			return
		}

		mntnsID, err := mntnsIDField.Uint64(data)
		if err != nil {
			api.Errorf("getting mntns_id from corresponding field: %v", err)
			return
		}

		name, err := nameField.String(data, 64)
		if err != nil {
			api.Errorf("getting name from corresponding field: %v", err)
			return
		}

		switch eventType {
		case "CREATED":
			api.Debugf("attaching %v", name)
			err = t.attach(mntnsID)
			if err != nil {
				api.Errorf("attaching container %v: %v", name, err)
				return
			}
		case "DELETED":
			api.Debugf("detaching %v", name)
			err := t.detach(mntnsID)
			if err != nil {
				api.Errorf("detaching container %v: %v", name, err)
				return
			}
		default:
			api.Errorf("unknown event type for container %v: got %v, expected CREATED or DELETED", name, eventType)
		}
	}, 0)

	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	t.readers.Range(func(key, value any) bool {
		mntnsID := key.(uint64)
		reader := value.(*containerRingReader)

		events, err := t.read(mntnsID, reader)
		if err != nil {
			api.Errorf("reading container: %v", err)
			return true
		}

		reader.perfReader.Close()

		for _, event := range events {
			packet, err := dsOutput.NewPacketSingle()
			if err != nil {
				api.Errorf("creating datasource packet: %v", err)
				continue
			}

			fields.mntnsID.SetUint64(api.Data(packet), event.mountNsID)
			fields.cpu.SetUint16(api.Data(packet), event.cpu)
			fields.pid.SetUint32(api.Data(packet), event.pid)
			fields.comm.SetString(api.Data(packet), event.comm)
			fields.syscall.SetString(api.Data(packet), event.syscall)
			fields.parameters.SetString(api.Data(packet), paramsToString(event.parameters))
			fields.ret.SetString(api.Data(packet), event.retval)

			dsOutput.EmitAndRelease(api.Packet(packet))
		}

		return true
	})

	return 0
}

func main() {}

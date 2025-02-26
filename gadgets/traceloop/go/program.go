// Copyright 2024 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
	tracelooptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// These consts must match the content of program.bpf.c.
const (
	useNullByteLength        uint64 = 0x0fffffffffffffff
	useRetAsParamLength      uint64 = 0x0ffffffffffffffe
	useArgIndexAsParamLength uint64 = 0x0ffffffffffffff0
	paramProbeAtExitMask     uint64 = 0xf000000000000000

	syscallEventTypeEnter uint8 = 0
	syscallEventTypeExit  uint8 = 1

	syscallArgs uint8 = 6

	syscallEventTypeNormal uint8 = 1
	syscallEventTypeCont   uint8 = 2
)

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

var (
	dsOutput api.DataSource
	fields   map[string]api.Field
)

type containerRingReader struct {
	innerBuffer api.Map
	perfReader  api.PerfReader
	mntnsID     uint64
}

type tracelooper struct {
	mapOfPerfBuffers api.Map

	// key:   cgroupID
	// value: *containerRingReader
	readers sync.Map
}

var t tracelooper

type traceloopSyscallEventContT struct {
	EventType          uint8
	Param              [128]uint8
	MonotonicTimestamp uint64
	Length             uint64
	Index              uint8
	Failed             uint8
	_                  [5]byte
}

type traceloopSyscallEventT struct {
	EventType          uint8
	Args               [6]uint64
	MonotonicTimestamp uint64
	BootTimestamp      uint64
	Pid                uint32
	Cpu                uint16
	Id                 uint16
	Comm               [16]uint8
	ContNr             uint8
	Typ                uint8
	_                  [61]byte
}

type syscallEvent struct {
	bootTimestamp      uint64
	monotonicTimestamp uint64
	typ                uint8
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

func (t *tracelooper) attach(cgroupID uint64, mntnsID uint64) error {
	perfBufferName := fmt.Sprintf("perf_buffer_%d", mntnsID)

	// 1. Create inner Map as perf buffer.
	// Keep the spec in sync with program.bpf.c.
	innerBuffer, err := api.NewMap(api.MapSpec{
		Name:       perfBufferName,
		Type:       api.PerfEventArray,
		KeySize:    uint32(4),
		ValueSize:  uint32(4),
	})
	if err != nil {
		return fmt.Errorf("creating map %s", fmt.Sprintf("perf_buffer_%d", mntnsID))
	}

	// 2. Use this inner Map to create the perf reader.
	perfReader, err := api.NewPerfReader(innerBuffer, uint32(64*os.Getpagesize()), true)
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

	t.readers.Store(cgroupID, &containerRingReader{
		innerBuffer: innerBuffer,
		perfReader:  perfReader,
		mntnsID:     mntnsID,
	})

	return nil
}

func (t *tracelooper) detach(mntnsID uint64) error {
	err := t.mapOfPerfBuffers.Delete(mntnsID)
	if err != nil {
		return fmt.Errorf("removing perf buffer from map with mntnsID %d: %v", mntnsID, err)
	}

	return nil
}

func fromCString(in []byte) string {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in)
}

func fromCStringN(in []byte, length int) string {
	l := len(in)
	if length < l {
		l = length
	}

	for i := 0; i < l; i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in[:l])
}

func wallTimeFromBootTime(ts uint64) eventtypes.Time {
	if ts == 0 {
		return eventtypes.Time(time.Now().UnixNano())
	}
	return eventtypes.Time(time.Unix(0, int64(ts)).Add(0/*timeDiff*/).UnixNano())
}

func timestampFromEvent(event *syscallEvent) eventtypes.Time {
	return wallTimeFromBootTime(event.bootTimestamp)
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

func (t *tracelooper) read(reader *containerRingReader) ([]*tracelooptypes.Event, error) {
	syscallContinuedEventsMap := make(map[uint64][]*syscallEventContinued)
	syscallEnterEventsMap := make(map[uint64][]*syscallEvent)
	syscallExitEventsMap := make(map[uint64][]*syscallEvent)
	var sysEventCont *traceloopSyscallEventContT
	events := make([]*tracelooptypes.Event, 0)
	var sysEvent *traceloopSyscallEventT

	err := reader.perfReader.Pause()
	if err != nil {
		return nil, err
	}

	records := make([][]byte, 0)
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
		records = append(records, record)
	}

	err = reader.perfReader.Resume()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		sysEvent = (*traceloopSyscallEventT)(unsafe.Pointer(&record[0]))

		switch sysEvent.EventType {
		case syscallEventTypeNormal:

			event := &syscallEvent{
				bootTimestamp:      sysEvent.BootTimestamp,
				monotonicTimestamp: sysEvent.MonotonicTimestamp,
				typ:                sysEvent.Typ,
				contNr:             sysEvent.ContNr,
				cpu:                sysEvent.Cpu,
				id:                 sysEvent.Id,
				pid:                sysEvent.Pid,
				comm:               fromCString(sysEvent.Comm[:]),
				mountNsID:          reader.mntnsID,
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
			default:
				// Rather than returning an error, we skip this event.
				api.Debugf("type %d is not a valid type for syscallEvent, received data are: %v", event.typ, record)

				continue
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

	// Let's try to publish the events we gathered.
	for enterTimestamp, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			event := &tracelooptypes.Event{
				Event: eventtypes.Event{
					Type:      eventtypes.NORMAL,
					Timestamp: timestampFromEvent(enterEvent),
				},
				CPU:           enterEvent.cpu,
				Pid:           enterEvent.pid,
				Comm:          enterEvent.comm,
				WithMountNsID: eventtypes.WithMountNsID{MountNsID: enterEvent.mountNsID},
				Syscall:       syscallName,
			}

			syscallDeclaration, err := api.GetSyscallDeclaration(event.Syscall)
			if err != nil {
				return nil, fmt.Errorf("getting syscall definition: %w", err)
			}

			parametersNumber := len(syscallDeclaration.Params)
			event.Parameters = make([]tracelooptypes.SyscallParam, parametersNumber)
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

				event.Parameters[i] = tracelooptypes.SyscallParam{
					Name:    paramName,
					Value:   paramValue,
					Content: paramContent,
				}
			}

			delete(syscallContinuedEventsMap, enterTimestamp)

			// There is no exit event for exit(), exit_group() and rt_sigreturn().
			if event.Syscall == "exit" || event.Syscall == "exit_group" || event.Syscall == "rt_sigreturn" {
				delete(syscallEnterEventsMap, enterTimestamp)

				// As there is no exit events for these syscalls,
				// then there is no return value.
				event.Retval = "X"

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

				event.Retval = retToStr(exitEvent.retval)

				delete(syscallEnterEventsMap, enterTimestamp)
				delete(syscallExitEventsMap, enterTimestamp)

				api.Debugf("%v", event)
				events = append(events, event)

				break
			}
		}
	}

	api.Debugf("len(events): %d; len(syscallEnterEventsMap): %d; len(syscallExitEventsMap): %d; len(syscallContinuedEventsMap): %d\n", len(events), len(syscallEnterEventsMap), len(syscallExitEventsMap), len(syscallContinuedEventsMap))

	// It is possible there are some incomplete events for two mains reasons:
	// 1. Traceloop was started in the middle of a syscall, then we will only get
	//    the exit but not the enter.
	// 2. The buffer is full and so it only remains some exit events and not the
	//    corresponding enter.
	// Rather than dropping these incomplete events, we just add them to the
	// events to be published.
	for _, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteEnterEvent := &tracelooptypes.Event{
				Event: eventtypes.Event{
					Type:      eventtypes.NORMAL,
					Timestamp: timestampFromEvent(enterEvent),
				},
				CPU:           enterEvent.cpu,
				Pid:           enterEvent.pid,
				Comm:          enterEvent.comm,
				WithMountNsID: eventtypes.WithMountNsID{MountNsID: enterEvent.mountNsID},
				Syscall:       syscallName,
				Retval:        "unfinished",
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

			incompleteExitEvent := &tracelooptypes.Event{
				Event: eventtypes.Event{
					Type:      eventtypes.NORMAL,
					Timestamp: timestampFromEvent(exitEvent),
				},
				CPU:           exitEvent.cpu,
				Pid:           exitEvent.pid,
				Comm:          exitEvent.comm,
				WithMountNsID: eventtypes.WithMountNsID{MountNsID: exitEvent.mountNsID},
				Syscall:       syscallName,
				Retval:        retToStr(exitEvent.retval),
			}

			events = append(events, incompleteExitEvent)

			api.Debugf("exitEvent(%q): %v\n", syscallName, exitEvent)
		}
	}

	// Sort all events by ascending timestamp.
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})

	// Remove timestamps if we couldn't get reliable ones
// 	if hasBpfKtimeGetBootNs() {
// 		for i := range events {
// 			events[i].Timestamp = 0
// 		}
// 	}

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
		name string
		kind api.FieldKind
	}{
		{
			name: "mntns_id",
			kind:  api.Kind_Uint64,
		},
		{
			name: "cpu",
			kind:  api.Kind_Uint16,
		},
		{
			name: "pid",
			kind:  api.Kind_Uint32,
		},
		{
			name: "comm",
			kind:  api.Kind_String,
		},
		{
			name: "syscall",
			kind:  api.Kind_String,
		},
		// TODO: Parameters []SyscallParam `json:"parameters,omitempty" column:"params,width:40"`
		{
			name: "ret",
			kind:  api.Kind_String,
		},
	}
	fields = make(map[string]api.Field, 0)
	for _, fieldInfo := range fieldsInfo {
		name := fieldInfo.name
		field, err := dsOutput.AddField(name, fieldInfo.kind)
		if err != nil {
			api.Errorf("adding %s field: %w", name, err)
			return 1
		}

		fields[name] = field
	}

	err = fields["mntns_id"].AddTag("type:gadget_mntns_id")
	if err != nil {
		api.Errorf("adding tag to mntns_id field: %w", err)
		return 1
	}

	return 0
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	var err error
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

		// We need to do so to avoid taking each time the same address.
		def := def
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

	cgroupIDField, err := ds.GetField("cgroup_id")
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
		eventType, err := eventTypeField.String(data, 7)
		if err != nil {
			api.Errorf("getting event_type from corresponding field: %v", err)
			return
		}

		cgroupID, err := cgroupIDField.Uint64(data)
		if err != nil {
			api.Errorf("getting cgroup_id from corresponding field: %v", err)
			return
		}

		name, err := nameField.String(data, 64)
		if err != nil {
			api.Errorf("getting name from corresponding field: %v", err)
			return
		}

		switch eventType {
		case "CREATED":
			mntnsID, err := mntnsIDField.Uint64(data)
			if err != nil {
				api.Errorf("getting mntns_id from corresponding field: %v", err)
				return
			}

			api.Debugf("attaching %v", name)
			err = t.attach(cgroupID, mntnsID)
			if err != nil {
				api.Errorf("attaching container %v: %v", name, err)
				return
			}
		case "DELETED":
			value, ok := t.readers.Load(cgroupID)
			if !ok {
				api.Errorf("container %v is unknown", name)
				return
			}

			reader := value.(*containerRingReader)
			api.Debugf("detaching %v", name)
			err := t.detach(reader.mntnsID)
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
	t.readers.Range(func(_, value any) bool {
		reader := value.(*containerRingReader)

		events, err := t.read(reader)
		if err != nil {
			api.Errorf("reading container: %v", err)
			return true
		}

		for _, event := range events {
			packet, err := dsOutput.NewPacketSingle()
			if err != nil {
				api.Errorf("creating datasource packet: %v", err)
				continue
			}

			fields["mntns_id"].SetUint64(api.Data(packet), event.WithMountNsID.MountNsID)
			fields["cpu"].SetUint16(api.Data(packet), event.CPU)
			fields["pid"].SetUint32(api.Data(packet), event.Pid)
			fields["comm"].SetString(api.Data(packet), event.Comm)
			fields["syscall"].SetString(api.Data(packet), event.Syscall)
			fields["ret"].SetString(api.Data(packet), event.Retval)

			dsOutput.EmitAndRelease(api.Packet(packet))
		}

		return true
	})

	return 0
}

func main() {}

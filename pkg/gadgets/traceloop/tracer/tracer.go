//go:build linux
// +build linux

// Copyright 2019-2022 The Inspektor Gadget authors
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

package tracer

// #include <linux/types.h>
// #include "./bpf/traceloop.h"
import "C"

import (
	"container/list"
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target ${TARGET} -cc clang traceloop ./bpf/traceloop.bpf.c -- -I./bpf/ -I../../../${TARGET}

var (
	useNullByteLength        uint64 = uint64(C.USE_NULL_BYTE_LENGTH)
	useRetAsParamLength      uint64 = uint64(C.USE_RET_AS_PARAM_LENGTH)
	useArgIndexAsParamLength uint64 = uint64(C.USE_ARG_INDEX_AS_PARAM_LENGTH)
	paramProbeAtExitMask     uint64 = uint64(C.PARAM_PROBE_AT_EXIT_MASK)
)

var (
	syscallEventTypeEnter uint8 = uint8(C.SYSCALL_EVENT_TYPE_ENTER)
	syscallEventTypeExit  uint8 = uint8(C.SYSCALL_EVENT_TYPE_EXIT)
	syscallEventTypeCont  uint8 = uint8(C.SYSCALL_EVENT_TYPE_CONT)
)

// This should match traceloop.h define SYSCALL_ARGS.
var syscallArgs uint8 = 6

var syscalls map[string]syscallDeclaration

type reader struct {
	reader          *perf.Reader
	previousHeadPos []uint64
}

type Tracer struct {
	enricher gadgets.DataEnricher

	spec *ebpf.CollectionSpec

	// We cannot know when Attach()/Detach() will be called, so it is better to
	// use lock to protect data structure which are not thought to be accessed
	// in parallel.
	objsLock  sync.Mutex
	objs      traceloopObjects
	enterLink link.Link
	exitLink  link.Link

	// Same comment than above, this map is designed to handled parallel access.
	readers sync.Map
}

type syscallEvent struct {
	timestamp uint64   `json:"timestamp,omitempty"`
	typ       uint8    `json:"type,omitempty"`
	contNr    uint8    `json:"contNr,omitempty"`
	cpu       uint16   `json:"cpu,omitempty"`
	id        uint16   `json:"id,omitempty"`
	pid       uint64   `json:"pid,omitempty"`
	comm      string   `json:"pcomm,omitempty"`
	args      []uint64 `json:"args,omitempty"`
	ret       uint64   `json:"ret,omitempty"`
	mountNsID uint64   `json:"mountnsid,omitempty"`
	retval    int      `json:"ret,omitempty"`
}

type syscallEventContinued struct {
	timestamp uint64 `json:"timestamp,omitempty"`
	index     uint8  `json:"index,omitempty"`
	param     string `json:"params,omitempty"`
}

func NewTracer(enricher gadgets.DataEnricher) (*Tracer, error) {
	t := &Tracer{
		enricher: enricher,
	}

	spec, err := loadTraceloop()
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	syscalls, err = gatherSyscalls()
	if err != nil {
		return nil, fmt.Errorf("error gathering syscall: %w", err)
	}

	// Fill the syscall map with specific syscall signatures.
	syscallsMapSpec := spec.Maps["syscalls"]
	for name, def := range syscallDefs {
		nr, err := libseccomp.GetSyscallFromName(name)
		if err != nil {
			return nil, fmt.Errorf("cannot get syscall number of %q: %w", name, err)
		}

		syscallsMapSpec.Contents = append(syscallsMapSpec.Contents, ebpf.MapKV{
			Key:   uint16(nr),
			Value: unsafe.Pointer(&def[0]),
		})
	}

	if err := spec.LoadAndAssign(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.enterLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: t.objs.IgTraceloopE,
	})
	if err != nil {
		return nil, fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.exitLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: t.objs.IgTraceloopX,
	})
	if err != nil {
		t.enterLink = gadgets.CloseLink(t.enterLink)

		return nil, fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.spec = spec

	return t, nil
}

func (t *Tracer) Stop() {
	t.enterLink = gadgets.CloseLink(t.enterLink)
	t.exitLink = gadgets.CloseLink(t.exitLink)

	t.readers.Range(func(key, _ any) bool {
		mntnsID, ok := key.(uint64)
		if ok {
			t.Detach(mntnsID)
		}

		return ok
	})

	t.objsLock.Lock()
	t.objs.Close()
	t.objsLock.Unlock()
}

func (t *Tracer) Attach(mntnsID uint64) error {
	outerMapSpec := t.spec.Maps["map_of_perf_buffers"]
	innerMapSpec := outerMapSpec.InnerMap

	innerBufferSpec := innerMapSpec.Copy()
	innerBufferSpec.Name = fmt.Sprintf("perf_buffer_%d", mntnsID)

	// 1. Create inner Map as perf buffer.
	innerBuffer, err := ebpf.NewMap(innerBufferSpec)
	if err != nil {
		return fmt.Errorf("error creating inner map: %w", err)
	}

	// 2. Use this inner Map to create the perf reader.
	perfReader, err := perf.NewReaderWithOptions(innerBuffer, gadgets.PerfBufferPages*os.Getpagesize(), perf.ReaderOptions{WriteBackward: true, OverWritable: true})
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}

	// 3. Add the inner map's file descriptor to outer map.
	t.objsLock.Lock()
	err = t.objs.MapOfPerfBuffers.Put(mntnsID, innerBuffer)
	t.objsLock.Unlock()
	if err != nil {
		return fmt.Errorf("error adding perf buffer to map with mntnsID %d", mntnsID)
	}

	t.readers.Store(mntnsID, &reader{
		reader:          perfReader,
		previousHeadPos: make([]uint64, getRingsNumber(perfReader)),
	})

	return nil
}

func (t *Tracer) Read(mntnsID uint64) ([]*types.Event, error) {
	syscallContinuedEventsMap := make(map[uint64][]*syscallEventContinued)
	syscallEventsMap := make(map[uint64][]*syscallEvent)
	eventsWaitingReturn := list.New()
	events := make([]*types.Event, 0)

	r, ok := t.readers.Load(mntnsID)
	if !ok {
		return nil, fmt.Errorf("no perf reader for %d", mntnsID)
	}

	reader, ok := r.(*reader)
	if !ok {
		return nil, errors.New("the map should only contain *reader")
	}

	// TODO Remove before merging.
	log.SetLevel(log.DebugLevel)

	if reader.reader == nil {
		log.Infof("reader for %v is nil, it was surely detached", mntnsID)

		return nil, nil
	}

	err := readOverWritable(reader, mntnsID, func(record perf.Record, size uint32) error {
		var cSyscallEvent C.struct_syscall_event_t
		var cSyscallContEvent C.struct_syscall_event_cont_t

		switch uintptr(size) {
		case alignSize(unsafe.Sizeof(cSyscallEvent)):
			cSyscallEvent = *(*C.struct_syscall_event_t)(unsafe.Pointer(&record.RawSample[0]))

			event := &syscallEvent{
				timestamp: uint64(cSyscallEvent.timestamp),
				typ:       uint8(cSyscallEvent.typ),
				contNr:    uint8(cSyscallEvent.cont_nr),
				cpu:       uint16(cSyscallEvent.cpu),
				id:        uint16(cSyscallEvent.id),
				pid:       uint64(cSyscallEvent.pid),
				comm:      C.GoString(&cSyscallEvent.comm[0]),
				mountNsID: mntnsID,
			}

			switch event.typ {
			case syscallEventTypeEnter:
				event.args = make([]uint64, syscallArgs)
				for i := uint8(0); i < syscallArgs; i++ {
					event.args[i] = uint64(cSyscallEvent.args[i])
				}
			case syscallEventTypeExit:
				event.ret = uint64(cSyscallEvent.args[0])
			default:
				// Rather than returning an error, we skip this event.
				// Indeed, I suspect this is caused because we copy the buffer while
				// it is being written, so we will get uncomplete data, thus it is
				// better to skip this event.
				log.Debugf("type %d is not a valid type for syscallEvent, received data are: %v", event.typ, record.RawSample)
				return nil
			}

			if _, ok := syscallEventsMap[event.timestamp]; !ok {
				syscallEventsMap[event.timestamp] = make([]*syscallEvent, 0)
			}

			syscallEventsMap[event.timestamp] = append(syscallEventsMap[event.timestamp], event)
		case alignSize(unsafe.Sizeof(cSyscallContEvent)):
			cSyscallContEvent = *(*C.struct_syscall_event_cont_t)(unsafe.Pointer(&record.RawSample[0]))

			event := &syscallEventContinued{
				timestamp: uint64(cSyscallContEvent.timestamp),
				index:     uint8(cSyscallContEvent.index),
			}

			if cSyscallContEvent.failed != 0 {
				event.param = "(Failed to dereference pointer)"
			} else if uint64(cSyscallContEvent.length) == useNullByteLength {
				// 0 byte at [C.PARAM_LENGTH - 1] is enforced in BPF code
				event.param = C.GoString(&cSyscallContEvent.param[0])
			} else {
				event.param = C.GoStringN(&cSyscallContEvent.param[0], C.int(cSyscallContEvent.length))
			}

			_, ok := syscallContinuedEventsMap[event.timestamp]
			if !ok {
				// Just create a 0 elements slice for the moment, the ContNr will be
				// checked later.
				syscallContinuedEventsMap[event.timestamp] = make([]*syscallEventContinued, 0)
			}

			syscallContinuedEventsMap[event.timestamp] = append(syscallContinuedEventsMap[event.timestamp], event)
		default:
			log.Debugf("size %d does not correspond to any expected element, which are %d and %d; received data are: %v", size, unsafe.Sizeof(cSyscallEvent), unsafe.Sizeof(cSyscallContEvent), record.RawSample)
		}

		return nil
	})
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			// nothing to do, we're done
			return nil, nil
		}

		return nil, fmt.Errorf("error reading backward over writable perf ring buffer: %w", err)
	}

	// Let's try to publish the events we gathered.
	for timestamp := range syscallEventsMap {
		for _, syscallEvent := range syscallEventsMap[timestamp] {
			syscallName, err := syscallGetName(syscallEvent.id)
			if err != nil {
				return nil, fmt.Errorf("cannot get name syscall name for syscall ID %d: %w", syscallEvent.id, err)
			}

			event := &types.Event{
				Event: eventtypes.Event{
					Type: eventtypes.NORMAL,
				},
				Timestamp: timestamp,
				CPU:       syscallEvent.cpu,
				Pid:       syscallEvent.pid,
				Comm:      syscallEvent.comm,
				MountNsID: syscallEvent.mountNsID,
				Name:      syscallName,
			}

			switch syscallEvent.typ {
			case syscallEventTypeEnter:
				log.Debugf("\tevent: %v", event)
				parametersNumber, err := syscallGetParametersNumber(syscalls, event.Name)
				if err != nil {
					return nil, fmt.Errorf("error getting syscall parameters number: %w", err)
				}

				event.Parameters = make([]types.SyscallParam, parametersNumber)
				log.Debugf("\tevent parametersNumber: %d", parametersNumber)
				for i := uint8(0); i < parametersNumber; i++ {
					paramName, err := syscallGetParameterName(syscalls, event.Name, i)
					if err != nil {
						return nil, fmt.Errorf("error getting syscall parameter name: %w", err)
					}
					log.Debugf("\t\tevent paramName: %q", paramName)

					paramValue := fmt.Sprintf("%d", syscallEvent.args[i])
					log.Debugf("\t\tevent paramValue: %q", paramValue)

					for _, syscallContEvent := range syscallContinuedEventsMap[timestamp] {
						if syscallContEvent.index == i {
							paramValue = fmt.Sprintf("%s %s", paramValue, syscallContEvent.param)
							log.Debugf("\t\t\tevent paramValue: %q", paramValue)

							break
						}
					}

					event.Parameters[i] = types.SyscallParam{
						Name:  paramName,
						Value: paramValue,
					}
				}

				eventsWaitingReturn.PushBack(event)

				delete(syscallContinuedEventsMap, timestamp)
				delete(syscallEventsMap, timestamp)
			case syscallEventTypeExit:
				for it := eventsWaitingReturn.Front(); it != nil; it = it.Next() {
					event, ok := it.Value.(*types.Event)
					if !ok {
						return nil, fmt.Errorf("list should only contain types.Event")
					}

					if event.Timestamp <= syscallEvent.timestamp &&
						event.Name == syscallName &&
						event.Pid == syscallEvent.pid {
						event.Retval = syscallEvent.retval

						eventsWaitingReturn.Remove(it)
						delete(syscallEventsMap, timestamp)

						if t.enricher != nil {
							t.enricher.Enrich(&event.CommonData, event.MountNsID)
						}
						log.Debugf("%v", event)
						events = append(events, event)

						break
					}
				}
			default:
				return nil, fmt.Errorf("type %v is not a valid type for syscallEvent, this should not occur", event.Type)
			}
		}
	}

	log.Debugf("len(syscallEventsMap): %d; len(syscallContinuedEventsMap): %d\n", len(syscallEventsMap), len(syscallContinuedEventsMap))

	return events, nil
}

func (t *Tracer) Detach(mntnsID uint64) error {
	r, ok := t.readers.Load(mntnsID)
	if !ok {
		return fmt.Errorf("no reader for mntnsID %d", mntnsID)
	}

	reader, ok := r.(*reader)
	if !ok {
		return errors.New("the map should only contain *reader")
	}

	reader.reader.Close()
	reader.reader = nil

	t.readers.Delete(mntnsID)

	t.objsLock.Lock()
	err := t.objs.MapOfPerfBuffers.Delete(mntnsID)
	t.objsLock.Unlock()
	if err != nil {
		return fmt.Errorf("error removing perf buffer to map with mntnsID %d", mntnsID)
	}

	log.Infof("succesfully detached %v", mntnsID)

	return nil
}

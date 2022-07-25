// Copyright 2019-2021 The Inspektor Gadget authors
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

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	log "github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang seccomp ./bpf/seccomp.c -- -I./bpf/ -I../../../../${TARGET}

// #include "bpf/seccomp-common.h"
import "C"

const (
	BPFProgName = "tracepoint__raw_syscalls__sys_enter"
	BPFMapName  = "syscalls_per_mntns"
)

type Tracer struct {
	collection *ebpf.Collection
	seccompMap *ebpf.Map

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link
}

func NewTracer() (*Tracer, error) {
	spec, err := loadSeccomp()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}

	t := &Tracer{
		collection: coll,
		seccompMap: coll.Maps[BPFMapName],
	}

	t.seccompMap.Update(uint64(0), [C.SYSCALLS_MAP_VALUE_SIZE]byte{}, ebpf.UpdateAny)

	tracepointProg, ok := coll.Programs[BPFProgName]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPFProgName)
	}

	t.progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: tracepointProg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open tracepoint: %w", err)
	}

	return t, nil
}

func (t *Tracer) Peek(mntns uint64) []byte {
	b, err := t.seccompMap.LookupBytes(mntns)
	if err != nil {
		log.Errorf("Error while looking up the seccomp map: %s", err)
		return make([]byte, C.SYSCALLS_COUNT)
	}
	// LookupBytes does not return an error when the entry is not found, so
	// we need to test b==nil too
	if b == nil {
		// The container just hasn't done any syscall
		log.Errorf("No syscall found with mntns %d", mntns)
		return make([]byte, C.SYSCALLS_COUNT)
	}
	if len(b) < C.SYSCALLS_COUNT {
		log.Errorf("Error while looking up the seccomp map: wrong length: %d", len(b))
		return make([]byte, C.SYSCALLS_COUNT)
	}
	return b[:C.SYSCALLS_COUNT]
}

func (t *Tracer) Delete(mntns uint64) {
	t.seccompMap.Delete(mntns)
}

func (t *Tracer) Close() {
	t.progLink = gadgets.CloseLink(t.progLink)
	t.collection.Close()
}

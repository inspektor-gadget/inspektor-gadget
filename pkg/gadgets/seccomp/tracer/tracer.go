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
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

// #include "bpf/seccomp-common.h"
import "C"

const (
	BPF_PROG_NAME = "tracepoint__raw_syscalls__sys_enter"
	BPF_MAP_NAME  = "syscalls_per_mntns"
)

type Tracer struct {
	collection *ebpf.Collection
	seccompMap *ebpf.Map
}

func NewTracer() (*Tracer, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %s", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %s", err)
	}

	t := &Tracer{
		collection: coll,
		seccompMap: coll.Maps[BPF_MAP_NAME],
	}

	t.seccompMap.Update(uint64(0), [C.SYSCALLS_MAP_VALUE_SIZE]byte{}, ebpf.UpdateAny)

	tracepointProg, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPF_PROG_NAME)
	}

	_, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: tracepointProg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open tracepoint: %s", err)
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
		return make([]byte, C.SYSCALLS_COUNT)
	}
	if len(b) < C.SYSCALLS_COUNT {
		log.Errorf("Error while looking up the seccomp map: wrong length: %d", len(b))
		return make([]byte, C.SYSCALLS_COUNT)
	}
	return b[:C.SYSCALLS_COUNT]
}

func (t *Tracer) Close() {
	t.collection.Close()
}

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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	libseccomp "github.com/seccomp/libseccomp-golang"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang seccomp ./bpf/seccomp.bpf.c -- -I./bpf/ -I../../../../${TARGET}

const (
	// Please update these values also in bpf/seccomp-common.h
	syscallsCount              = 500
	syscallsMapValueFooterSize = 1
	syscallsMapValueSize       = syscallsCount + syscallsMapValueFooterSize
)

type Tracer struct {
	objs seccompObjects

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link

	// We keep references to mountns of containers we attach to, so we
	// can collect information afterwards
	containers map[*containercollection.Container][]string
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.start(); err != nil {
		t.Close()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) start() error {
	spec, err := loadSeccomp()
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	if err := spec.LoadAndAssign(&t.objs, nil); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.objs.SyscallsPerMntns.Update(uint64(0), [syscallsMapValueSize]byte{}, ebpf.UpdateAny)

	t.progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: t.objs.IgSeccompE,
	})
	if err != nil {
		return fmt.Errorf("failed to open tracepoint: %w", err)
	}

	return nil
}

func syscallArrToNameList(v []byte) []string {
	names := []string{}
	for i, val := range v {
		if val == 0 {
			continue
		}
		call1 := libseccomp.ScmpSyscall(i)
		name, err := call1.GetName()
		if err != nil {
			name = fmt.Sprintf("syscall%d", i)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (t *Tracer) Peek(mntns uint64) ([]string, error) {
	b, err := t.objs.SyscallsPerMntns.LookupBytes(mntns)
	if err != nil {
		return nil, fmt.Errorf("looking up the seccomp map: %w", err)
	}
	// LookupBytes does not return an error when the entry is not found, so
	// we need to test b==nil too
	if b == nil {
		// The container just hasn't done any syscall
		return nil, fmt.Errorf("no syscall found")
	}
	if len(b) < syscallsCount {
		return nil, fmt.Errorf("looking up the seccomp map: wrong length: %d", len(b))
	}
	return syscallArrToNameList(b[:syscallsCount]), nil
}

func (t *Tracer) Delete(mntns uint64) {
	t.objs.SyscallsPerMntns.Delete(mntns)
}

func (t *Tracer) Close() {
	t.progLink = gadgets.CloseLink(t.progLink)
	t.objs.Close()
}

// ---

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	t := &Tracer{
		containers: make(map[*containercollection.Container][]string),
	}
	return t, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	return nil
}

func (t *Tracer) Stop() {
}

func (t *Tracer) Start() error {
	if err := t.start(); err != nil {
		t.Stop()
		return err
	}
	return nil
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	t.containers[container] = nil
	return nil
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	res, err := t.Peek(container.Mntns)
	if err != nil {
		t.containers[container] = []string{err.Error()}
		return nil
	}
	t.containers[container] = res
	return nil
}

func (t *Tracer) Result() ([]byte, error) {
	out := make(map[string][]string)
	for container, result := range t.containers {
		out[container.Name] = result
	}
	return json.MarshalIndent(out, "", "  ")
}

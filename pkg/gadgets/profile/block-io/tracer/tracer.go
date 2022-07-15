//go:build linux
// +build linux

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

// #include <linux/types.h>
// #include "./bpf/biolatency.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/block-io/types"
	"github.com/moby/moby/pkg/parsers/kernel"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang biolatency ./bpf/biolatency.bpf.c -- -I./bpf/ -I../../../../${TARGET}
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang biolatencyBefore ./bpf/biolatency.bpf.c -- -I./bpf/ -I../../../../${TARGET} -DKERNEL_BEFORE_5_11

type Tracer struct {
	objs                biolatencyObjects
	blockRqCompleteLink link.Link
	blockRqInsertLink   link.Link
	blockRqIssueLink    link.Link
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func getReport(histMap *ebpf.Map) (types.Report, error) {
	report := types.Report{
		ValType: "usecs",
	}

	key := C.struct_hist_key{}

	err := histMap.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		return types.Report{}, fmt.Errorf("error getting next key: %w", err)
	}

	hist := C.struct_hist{}
	if err := histMap.Lookup(key, unsafe.Pointer(&hist)); err != nil {
		return types.Report{}, err
	}

	data := []types.Data{}
	indexMax := 0
	for i, val := range hist.slots {
		if val > 0 {
			indexMax = i
		}

		data = append(data, types.Data{
			Count:         uint64(val),
			IntervalStart: (uint64(1) << (i + 1)) >> 1,
			IntervalEnd:   (uint64(1) << (i + 1)) - 1,
		})
	}

	report.Data = data[:indexMax]

	return report, nil
}

func (t *Tracer) Stop() (string, error) {
	t.blockRqCompleteLink = gadgets.CloseLink(t.blockRqCompleteLink)
	t.blockRqInsertLink = gadgets.CloseLink(t.blockRqInsertLink)
	t.blockRqIssueLink = gadgets.CloseLink(t.blockRqIssueLink)

	defer t.objs.Close()

	if t.objs.Hists == nil {
		return "", nil
	}
	report, err := getReport(t.objs.Hists)
	if err != nil {
		return "", err
	}

	output, err := json.Marshal(report)

	return string(output), err
}

func (t *Tracer) start() error {
	var spec *ebpf.CollectionSpec

	version, err := kernel.GetKernelVersion()
	if err != nil {
		return err
	}

	if kernel.CompareKernelVersion(*version, kernel.VersionInfo{Kernel: 5, Major: 11, Minor: 0}) == -1 {
		spec, err = loadBiolatencyBefore()
	} else {
		spec, err = loadBiolatency()
	}

	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	if err := spec.LoadAndAssign(&t.objs, nil); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	blockRqCompleteLink, err := link.AttachTracing(link.TracingOptions{Program: t.objs.BlockRqComplete})
	if err != nil {
		return fmt.Errorf("error attaching tracing: %w", err)
	}
	t.blockRqCompleteLink = blockRqCompleteLink

	blockRqInsertLink, err := link.AttachTracing(link.TracingOptions{Program: t.objs.BlockRqInsert})
	if err != nil {
		return fmt.Errorf("error attaching tracing: %w", err)
	}
	t.blockRqInsertLink = blockRqInsertLink

	blockRqIssueLink, err := link.AttachTracing(link.TracingOptions{Program: t.objs.BlockRqIssue})
	if err != nil {
		return fmt.Errorf("error attaching tracing: %w", err)
	}
	t.blockRqIssueLink = blockRqIssueLink

	return nil
}

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
)

const (
	BPF_PROG_NAME = "tracepoint__sys_enter_close"
)

type Tracer struct {
	collection *ebpf.Collection

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link
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
	}

	tracepointProg, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPF_PROG_NAME)
	}

	t.progLink, err = link.Tracepoint("syscalls", "sys_enter_close", tracepointProg)
	if err != nil {
		return nil, fmt.Errorf("failed to open tracepoint: %s", err)
	}

	return t, nil
}

func (t *Tracer) Close() {
	t.progLink.Close()
	t.collection.Close()
}

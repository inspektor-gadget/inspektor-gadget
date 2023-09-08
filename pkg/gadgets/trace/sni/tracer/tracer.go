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
	"context"
	"errors"
	"fmt"
	"unsafe"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ../../../internal/networktracer/clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event_t snisnoop ./bpf/snisnoop.c -- $CLANG_OS_FLAGS -I./bpf/ -I../../../../../include/"

const (
	TLSMaxServerNameLen = len(snisnoopEventT{}.Name)
)

type Tracer struct {
	*networktracer.Tracer[types.Event]

	ctx    context.Context
	cancel context.CancelFunc
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.install(); err != nil {
		t.Close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
}

func parseSNIEvent(sample []byte, netns uint64) (*types.Event, error) {
	bpfEvent := (*snisnoopEventT)(unsafe.Pointer(&sample[0]))
	if len(sample) < int(unsafe.Sizeof(*bpfEvent)) {
		return nil, errors.New("invalid sample size")
	}

	timestamp := gadgets.WallTimeFromBootTime(bpfEvent.Timestamp)

	name := gadgets.FromCString(bpfEvent.Name[:])
	if len(name) == 0 {
		return nil, nil
	}

	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: timestamp,
		},
		Pid:           bpfEvent.Pid,
		Tid:           bpfEvent.Tid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
		Comm:          gadgets.FromCString(bpfEvent.Task[:]),

		Name: name,
	}

	return &event, nil
}

// --- Registry changes

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	if err := t.install(); err != nil {
		t.Close()
		return fmt.Errorf("installing tracer: %w", err)
	}

	t.ctx, t.cancel = gadgetcontext.WithTimeoutOrCancel(gadgetCtx.Context(), gadgetCtx.Timeout())
	return nil
}

func (t *Tracer) install() error {
	spec, err := loadSnisnoop()
	if err != nil {
		return fmt.Errorf("loading asset: %w", err)
	}

	networkTracer, err := networktracer.NewTracer[types.Event]()
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
	}
	err = networkTracer.Run(spec, types.Base, parseSNIEvent)
	if err != nil {
		return fmt.Errorf("setting network tracer spec: %w", err)
	}
	t.Tracer = networkTracer
	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	<-t.ctx.Done()
	return nil
}

func (t *Tracer) Close() {
	if t.cancel != nil {
		t.cancel()
	}

	if t.Tracer != nil {
		t.Tracer.Close()
	}
}

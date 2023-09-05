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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ../../../internal/networktracer/clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event_t network ./bpf/network.c -- $CLANG_OS_FLAGS -I./bpf/ -I../../../internal/socketenricher/bpf"

type Tracer struct {
	*networktracer.Tracer[types.Event]

	ctx    context.Context
	cancel context.CancelFunc
}

func NewTracer() (_ *Tracer, err error) {
	t := &Tracer{}

	if err := t.install(); err != nil {
		t.Close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
}

func pktTypeString(pktType int) string {
	// pkttype definitions:
	// https://github.com/torvalds/linux/blob/v5.14-rc7/include/uapi/linux/if_packet.h#L26
	pktTypeNames := []string{
		"HOST",
		"BROADCAST",
		"MULTICAST",
		"OTHERHOST",
		"OUTGOING",
		"LOOPBACK",
		"USER",
		"KERNEL",
	}
	pktTypeStr := fmt.Sprintf("UNKNOWN#%d", pktType)
	if uint(pktType) < uint(len(pktTypeNames)) {
		pktTypeStr = pktTypeNames[pktType]
	}
	return pktTypeStr
}

func parseNetEvent(sample []byte, netns uint64) (*types.Event, error) {
	bpfEvent := (*networkEventT)(unsafe.Pointer(&sample[0]))
	if len(sample) < int(unsafe.Sizeof(*bpfEvent)) {
		return nil, errors.New("invalid sample size")
	}

	timestamp := gadgets.WallTimeFromBootTime(bpfEvent.Timestamp)

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, gadgets.Htonl(bpfEvent.Ip))

	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: timestamp,
		},
		PktType: pktTypeString(int(bpfEvent.PktType)),
		Proto:   gadgets.ProtoString(int(bpfEvent.Proto)),
		Port:    gadgets.Htons(bpfEvent.Port),
		DstEndpoint: eventtypes.L3Endpoint{
			Addr:    ip.String(),
			Version: 4,
		},

		Pid:           bpfEvent.Pid,
		Tid:           bpfEvent.Tid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
		Comm:          gadgets.FromCString(bpfEvent.Task[:]),
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
	spec, err := loadNetwork()
	if err != nil {
		return fmt.Errorf("loading asset: %w", err)
	}

	networkTracer, err := networktracer.NewTracer(
		spec,
		types.Base,
		parseNetEvent,
	)
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
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

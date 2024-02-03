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

//go:build !withoutebpf

package tchandler

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	tccore "github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

const (
	// filterInfo is a combination of priority and protocol: priority << 16 | proto. See
	// https://github.com/iproute2/iproute2/blob/f443565f8df65e7d3b3e7cb5f4e94aec1e12d067/tc/tc_filter.c#L147
	// https://github.com/iproute2/iproute2/blob/f443565f8df65e7d3b3e7cb5f4e94aec1e12d067/tc/tc_filter.c#L68
	// - Protocol: The protocol this classifier will accept. We want to match all packets.
	// Hence, use ETH_P_ALL.
	// - Priority: The priority of this filter. We use 1 as we don't install other filters in
	// the same interface.
	filterInfo = uint32(0x1<<16 | 0x0300) // priority (1) << 16 | proto (htons(ETH_P_ALL))

	filterHandleMax = 128
)

func ptr[T any](v T) *T {
	return &v
}

type AttachmentDirection int

const (
	AttachmentDirectionUnspec AttachmentDirection = iota
	AttachmentDirectionIngress
	AttachmentDirectionEgress
)

// createClsActQdisc creates a clsact qdisc on the given interface.
func createClsActQdisc(tcnl *tc.Tc, iface *net.Interface) (*tc.Object, error) {
	// Install Qdisc on interface
	qdisc := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  tccore.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Add(qdisc); err != nil {
		return nil, fmt.Errorf("adding clsact qdisc to %s: %w", iface.Name, err)
	}

	return qdisc, nil
}

// addTCFilter adds a filter to the given interface. It returns the filter object or an error. In
// order to allow multiple filters on the same interface, it tries to add the filter with different
// handles until it succeeds or it has tried filterHandleMax times.
func addTCFilter(tcnl *tc.Tc, prog *ebpf.Program, iface *net.Interface, dir AttachmentDirection) (*tc.Object, error) {
	info, _ := prog.Info()
	var parent uint32

	switch dir {
	case AttachmentDirectionIngress:
		parent = tccore.BuildHandle(tc.HandleRoot, tc.HandleMinIngress)
	case AttachmentDirectionEgress:
		parent = tccore.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)
	default:
		return nil, fmt.Errorf("invalid filter direction")
	}

	for handle := uint32(0x1); handle < filterHandleMax; handle++ {
		filter := &tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  handle,
				Parent:  parent,
				Info:    filterInfo,
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    ptr(uint32(prog.FD())),
					Name:  ptr(info.Name),
					Flags: ptr(uint32(tc.BpfActDirect)),
				},
			},
		}

		if err := tcnl.Filter().Add(filter); err == nil {
			return filter, nil
		} else if !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("creating filter (too many tries)")
}

// Copyright 2022 The Inspektor Gadget authors
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

package enricher

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang socketsmap ./bpf/sockets-map.bpf.c -- -I./bpf/ -I../../../../ -I../../../../${TARGET}

const (
	BPFMapName = "sockets"
)

// SocketsMap creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code:
//
//	TODO
type SocketsMap struct {
	objs      socketsmapObjects
	ipv4Entry link.Link
	ipv4Exit  link.Link
	ipv6Entry link.Link
	ipv6Exit  link.Link
}

func NewSocketsMap() (*SocketsMap, error) {
	sm := &SocketsMap{}

	spec, err := loadSocketsmap()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	if err := spec.LoadAndAssign(&sm.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	sm.ipv4Entry, err = link.Kprobe("inet_bind", sm.objs.IgBindIpv4E, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}

	sm.ipv4Exit, err = link.Kretprobe("inet_bind", sm.objs.IgBindIpv4X, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}

	sm.ipv6Entry, err = link.Kprobe("inet6_bind", sm.objs.IgBindIpv6E, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}

	sm.ipv6Exit, err = link.Kretprobe("inet6_bind", sm.objs.IgBindIpv6X, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}

	fmt.Printf("SocketsMap: kprobes attached\n")

	return sm, nil
}

func (sm *SocketsMap) SocketsMap() *ebpf.Map {
	return sm.objs.socketsmapMaps.Sockets
}

func (sm *SocketsMap) Close() {
	if sm == nil {
		return
	}
	sm.ipv4Entry = gadgets.CloseLink(sm.ipv4Entry)
	sm.ipv4Exit = gadgets.CloseLink(sm.ipv4Exit)
	sm.ipv6Entry = gadgets.CloseLink(sm.ipv6Entry)
	sm.ipv6Exit = gadgets.CloseLink(sm.ipv6Exit)
	sm.objs.Close()
}

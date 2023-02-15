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

package socketenricher

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang socketenricher ./bpf/sockets-map.bpf.c -- -I./bpf/ -I../../../ -I../../../${TARGET}

// SocketEnricher creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code in the dns and
// sni gadgets.
type SocketEnricher struct {
	objs  socketenricherObjects
	links []link.Link
}

func (se *SocketEnricher) SocketsMap() *ebpf.Map {
	return se.objs.Sockets
}

func NewSocketEnricher() (*SocketEnricher, error) {
	se := &SocketEnricher{}

	if err := se.start(); err != nil {
		se.Close()
		return nil, err
	}

	return se, nil
}

func (se *SocketEnricher) start() error {
	spec, err := loadSocketenricher()
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	if err := spec.LoadAndAssign(&se.objs, nil); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	var l link.Link

	// bind
	l, err = link.Kprobe("inet_bind", se.objs.IgBindIpv4E, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet_bind", se.objs.IgBindIpv4X, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv4 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_bind", se.objs.IgBindIpv6E, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet6_bind", se.objs.IgBindIpv6X, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// connect
	l, err = link.Kprobe("tcp_v4_connect", se.objs.IgTcpcV4CoE, nil)
	if err != nil {
		return fmt.Errorf("error opening connect ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_v4_connect", se.objs.IgTcpcV4CoX, nil)
	if err != nil {
		return fmt.Errorf("error opening connect ipv4 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("tcp_v6_connect", se.objs.IgTcpcV6CoE, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 connect kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_v6_connect", se.objs.IgTcpcV6CoX, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 connect kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// udp_sendmsg
	l, err = link.Kprobe("udp_sendmsg", se.objs.IgUdpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("error opening udp_sendmsg ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("udpv6_sendmsg", se.objs.IgUdp6Sendmsg, nil)
	if err != nil {
		return fmt.Errorf("error opening udpv6_sendmsg ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	// release
	l, err = link.Kprobe("inet_release", se.objs.IgFreeIpv4E, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv4 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_release", se.objs.IgFreeIpv6E, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	return nil
}

func (se *SocketEnricher) Close() {
	for _, l := range se.links {
		gadgets.CloseLink(l)
	}
	se.links = nil
	se.objs.Close()
}

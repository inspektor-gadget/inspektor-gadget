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
	"io"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang socketenricher ./bpf/sockets-map.bpf.c -- -I./bpf/ -I../../../ -I../../../${TARGET}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang extension ./bpf/extension.bpf.c -- -I./bpf/

const (
	BPFMapName = "sockets"
)

// SocketEnricher creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code:
//
//	TODO
type SocketEnricher struct {
	objs  socketenricherObjects
	links []link.Link

	extensionSpec *ebpf.CollectionSpec
}

func NewSocketsMap() (*SocketEnricher, error) {
	se := &SocketEnricher{}

	var err error
	se.extensionSpec, err = loadExtension()
	if err != nil {
		return nil, fmt.Errorf("failed to load extension: %w", err)
	}

	spec, err := loadSocketenricher()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	if err := spec.LoadAndAssign(&se.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	var l link.Link

	// bind
	l, err = link.Kprobe("inet_bind", se.objs.IgBindIpv4E, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet_bind", se.objs.IgBindIpv4X, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_bind", se.objs.IgBindIpv6E, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet6_bind", se.objs.IgBindIpv6X, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	// connect
	l, err = link.Kprobe("tcp_v4_connect", se.objs.IgTcpcV4CoE, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening connect ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_v4_connect", se.objs.IgTcpcV4CoX, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening connect ipv4 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("tcp_v6_connect", se.objs.IgTcpcV6CoE, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 connect kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_v6_connect", se.objs.IgTcpcV6CoX, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 connect kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// release
	l, err = link.Kprobe("inet_release", se.objs.IgFreeIpv4E, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv4 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_release", se.objs.IgFreeIpv6E, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ipv6 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	return se, nil
}

func (se *SocketEnricher) SocketsMap() *ebpf.Map {
	return se.objs.socketenricherMaps.Sockets
}

type ExtensionConnection struct {
	closers []io.Closer
}

func (ec ExtensionConnection) Close() error {
	for _, closer := range ec.closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (se *SocketEnricher) PlugExtension(target *ebpf.Program, netns uint64) (io.Closer, error) {
	spec := se.extensionSpec.Copy()

	consts := map[string]interface{}{
		"current_netns": netns,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return nil, fmt.Errorf("error RewriteConstants during PlugExtension: %w", err)
	}

	for funcName, _ := range spec.Programs {
		if !strings.HasPrefix(funcName, "gadget_") {
			continue
		}
		spec.Programs[funcName].AttachTarget = target
	}

	mapReplacements := map[string]*ebpf.Map{
		"sockets": se.objs.Sockets,
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("error loading program: %w", err)
	}
	defer coll.Close()

	ec := ExtensionConnection{}
	for funcName, replacement := range coll.Programs {
		if !strings.HasPrefix(funcName, "gadget_") {
			continue
		}

		freplace, err := link.AttachFreplace(target, funcName, replacement)
		if err != nil {
			return nil, fmt.Errorf("error replacing function %q: %w", funcName, err)
		}
		ec.closers = append(ec.closers, freplace)
	}

	return ec, nil
}

func (se *SocketEnricher) Close() {
	if se == nil {
		return
	}
	for _, l := range se.links {
		gadgets.CloseLink(l)
	}
	se.links = nil
	se.objs.Close()
}

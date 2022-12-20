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

package endpointcollection

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang endpointcollection ./bpf/endpointcollection.bpf.c -- -I./bpf/ -I../../../ -I../../../${TARGET}

// EndpointCollection creates a LPM map giving an endpoint id for each IP.
//
// This makes it possible for network gadgets to access that information and
// aggregate statistics by endpoint.
type EndpointCollection struct {
	objs endpointcollectionObjects

	mu        sync.Mutex
	nextID    uint64
	endpoints map[string]Endpoint
}

type Endpoint struct {
	ID    uint64
	Name  string
	IPNet net.IPNet
}

func (ec *EndpointCollection) EndpointsMap() *ebpf.Map {
	return ec.objs.Endpoints
}

func NewEndpointCollection() (*EndpointCollection, error) {
	ec := &EndpointCollection{
		nextID:    1,
		endpoints: make(map[string]Endpoint),
	}

	if err := ec.start(); err != nil {
		ec.Close()
		return nil, err
	}

	return ec, nil
}

func (ec *EndpointCollection) start() error {
	spec, err := loadEndpointcollection()
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	if err := spec.LoadAndAssign(&ec.objs, nil); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	return nil
}

func (ec *EndpointCollection) Add(ipnet net.IPNet, name string) (uint64, error) {
	ip := ipnet.IP.To4()
	if ip == nil {
		// Only IPv4 is supported for now
		return 0, fmt.Errorf("invalid IP net %q", ipnet.String())
	}
	siz, _ := ipnet.Mask.Size()
	IPBigEndian := unsafe.Pointer(&ip[0])
	key := []uint32{uint32(siz), *(*uint32)(IPBigEndian)}
	newID := ec.nextID

	ec.mu.Lock()
	defer ec.mu.Unlock()

	err := ec.objs.Endpoints.Put(unsafe.Pointer(&key[0]), unsafe.Pointer(&newID))
	if err != nil {
		return 0, err
	}
	ec.nextID++
	ec.endpoints[name] = Endpoint{
		ID:    newID,
		Name:  name,
		IPNet: ipnet,
	}

	return newID, nil
}

func (ec *EndpointCollection) Remove(name string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	ep, ok := ec.endpoints[name]
	if !ok {
		return fmt.Errorf("name %q not found", name)
	}

	ip := ep.IPNet.IP.To4()
	if ip == nil {
		// Only IPv4 is supported for now
		return fmt.Errorf("invalid IP net %q", ep.IPNet.String())
	}
	IPBigEndian := unsafe.Pointer(&ip[0])
	siz, _ := ep.IPNet.Mask.Size()
	key := []uint32{uint32(siz), *(*uint32)(IPBigEndian)}

	err := ec.objs.Endpoints.Delete(unsafe.Pointer(&key[0]))
	if err != nil {
		return err
	}
	delete(ec.endpoints, name)

	return nil
}

func (ec *EndpointCollection) Lookup(id uint64) (string, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	for _, ep := range ec.endpoints {
		if ep.ID == id {
			return ep.Name, nil
		}
	}
	return "", fmt.Errorf("id %d not found", id)
}

func (ec *EndpointCollection) Close() {
	ec.objs.Close()
}

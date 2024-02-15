// Copyright 2022-2024 The Inspektor Gadget authors
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

// Package tchandler handles how SchedCLS programs are attached to containers and network
// interfaces. The behavior is very similar to the network tracer implemented in
// pkg/networktracer/tracer.go.
// The main difference is that SchedCLS programs need to be attached to network interfaces and can
// be attached on ingress or egress.
package tchandler

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} dispatcher ./bpf/dispatcher.bpf.c -- -I./bpf/

const (
	// Keep in sync with bpf/dispatcher.bpf.c
	tailCallMapName = "gadget_tail_call"
)

type attachment struct {
	// dispatcher is a small eBPF program we attach to each network interface. This programs
	// does a tail call to the gadget. The purpose of this program is to avoid loading multiple
	// instances of the gadget when there are different networking interfaces it must be
	// attached to.
	dispatcher dispatcherObjects
	// filter is the tc ebpf filter we attach to the network interface. This filter will execute
	// the dispatcher above.
	filter *tc.Object

	// users keeps track of the users' pid that have called Attach(). This can happen for when
	// there are several containers in a pod (sharing the netns, and hence the networking
	// interface). In this case we want to attach the program once.
	users map[uint32]struct{}
}

func (t *Handler) closeAttachment(a *attachment) {
	if a.filter != nil {
		t.tcnl.Filter().Delete(a.filter)
	}
	a.dispatcher.Close()
}

type Handler struct {
	// dispatcher map is a program array map with a single element that is used by the
	// dispatcher to perform a tail call to the gadget program.
	dispatcherMap *ebpf.Map
	// key: network interface name on the host side
	// value: attachment
	attachments map[string]*attachment

	// socket to talk to netlink
	// TODO: Currently we keep once instance of the socket for each Handler instance. Check if
	// it makes sense to move this to the tracer to have one single instance per gadget.
	// https://github.com/inspektor-gadget/inspektor-gadget/pull/2376#discussion_r1475472725
	tcnl *tc.Tc

	direction AttachmentDirection

	// mu protects attachments from concurrent access
	// AttachContainer and DetachContainer can be called in parallel
	mu sync.Mutex
}

func NewHandler(direction AttachmentDirection) (*Handler, error) {
	var err error
	var tcnl *tc.Tc

	// We need to create the client on the host network namespace, otherwise it's not able to
	// create the qdisc and filters.
	err = netnsenter.NetnsEnter(1, func() error {
		// Setup tc socket for communication with the kernel
		tcnl, err = tc.Open(&tc.Config{})
		if err != nil {
			return fmt.Errorf("opening rtnetlink socket: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	t := &Handler{
		attachments: make(map[string]*attachment),
		tcnl:        tcnl,
		direction:   direction,
	}
	defer func() {
		if err != nil {
			t.Close()
		}
	}()

	// Keep in sync with tail_call map in bpf/dispatcher.bpf.c
	dispatcherMapSpec := ebpf.MapSpec{
		Name:       tailCallMapName,
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	t.dispatcherMap, err = ebpf.NewMap(&dispatcherMapSpec)
	if err != nil {
		return nil, fmt.Errorf("creating tail call map: %w", err)
	}
	return t, nil
}

func (t *Handler) AttachProg(prog *ebpf.Program) error {
	return t.dispatcherMap.Update(uint32(0), uint32(prog.FD()), ebpf.UpdateAny)
}

func (t *Handler) newAttachment(pid uint32, iface *net.Interface, netns uint64, direction AttachmentDirection) (_ *attachment, err error) {
	a := &attachment{
		users: map[uint32]struct{}{pid: {}},
	}

	var qdisc *tc.Object

	defer func() {
		if err != nil {
			t.closeAttachment(a)
			if qdisc != nil {
				t.tcnl.Qdisc().Delete(qdisc)
			}
		}
	}()

	dispatcherSpec, err := loadDispatcher()
	if err != nil {
		return nil, err
	}

	consts := map[string]interface{}{
		"current_netns": uint32(netns),
	}
	if err := dispatcherSpec.RewriteConstants(consts); err != nil {
		return nil, fmt.Errorf("RewriteConstants while attaching to pid %d: %w", pid, err)
	}

	// We create the clsact qdisc and leak it. We can't remove it because we'll break any other
	// application (including other ig instances) that are using it.
	if qdisc, err = createClsActQdisc(t.tcnl, iface); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("creating clsact qdisc: %w", err)
	}

	optsIngress := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			tailCallMapName: t.dispatcherMap,
		},
	}
	if err = dispatcherSpec.LoadAndAssign(&a.dispatcher, &optsIngress); err != nil {
		return nil, fmt.Errorf("loading ebpf program: %w", err)
	}

	a.filter, err = addTCFilter(t.tcnl, a.dispatcher.IgNetDisp, iface, direction)
	if err != nil {
		return nil, fmt.Errorf("attaching ebpf program to interface %s: %w", iface.Name, err)
	}

	return a, nil
}

func (t *Handler) AttachContainer(container *containercollection.Container) error {
	// It's not clear what to do with hostNetwork containers. For now we just ignore them.
	if container.HostNetwork {
		return nil
	}

	pid := container.Pid

	netns, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		return fmt.Errorf("getting network interfaces on the host side for pid %d: %w", pid, err)
	}

	// If we're attaching a container, we need to invert ingress and egress because ingress on the
	// host end of the veth interface is egress on the container side and vice versa.
	var direction AttachmentDirection
	switch t.direction {
	case AttachmentDirectionIngress:
		direction = AttachmentDirectionEgress
	case AttachmentDirectionEgress:
		direction = AttachmentDirectionIngress
	}

	ifaces, err := containerutils.GetIfacePeers(int(pid))
	if err != nil {
		return fmt.Errorf("getting network namespace of pid %d: %w", pid, err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// We need to perform these operations from the host network namespace, otherwise we won't
	// be able to add the filter to the network interface.
	err = netnsenter.NetnsEnter(1, func() error {
		for _, iface := range ifaces {
			if a, ok := t.attachments[iface.Name]; ok {
				a.users[pid] = struct{}{}
				return nil
			}

			a, err := t.newAttachment(pid, iface, netns, direction)
			if err != nil {
				return fmt.Errorf("creating network handler attachment for container %s: %w",
					container.Runtime.ContainerName, err)
			}
			t.attachments[iface.Name] = a
		}

		return nil
	})
	return err
}

func (t *Handler) DetachContainer(container *containercollection.Container) error {
	// It's not clear what to do with hostNetwork containers. For now we just ignore them.
	if container.HostNetwork {
		return nil
	}

	pid := container.Pid

	t.mu.Lock()
	defer t.mu.Unlock()

	for ifacename, a := range t.attachments {
		if _, ok := a.users[pid]; ok {
			delete(a.users, pid)
			if len(a.users) == 0 {
				t.closeAttachment(a)
				delete(t.attachments, ifacename)
			}
			return nil
		}
	}
	return fmt.Errorf("pid %d is not attached", pid)
}

// AttachIface attaches the tracer to the given interface on the host. See AttachContainer() if you
// want to attach to a container.
func (t *Handler) AttachIface(iface *net.Interface) error {
	if _, ok := t.attachments[iface.Name]; ok {
		return nil
	}

	hostNs, err := containerutils.GetNetNs(int(1))
	if err != nil {
		return fmt.Errorf("getting network namespace of pid %d: %w", 1, err)
	}

	a, err := t.newAttachment(1, iface, hostNs, t.direction)
	if err != nil {
		return fmt.Errorf("creating network handler attachment for interface %s: %w", iface.Name, err)
	}
	t.attachments[iface.Name] = a

	return nil
}

func (t *Handler) DetachIface(iface *net.Interface) error {
	if a, ok := t.attachments[iface.Name]; ok {
		t.closeAttachment(a)
		delete(t.attachments, iface.Name)
		return nil
	}
	return fmt.Errorf("interface %s is not attached", iface.Name)
}

func (t *Handler) Close() {
	for _, a := range t.attachments {
		t.closeAttachment(a)
	}
	if t.dispatcherMap != nil {
		t.dispatcherMap.Close()
	}
	if t.tcnl != nil {
		t.tcnl.Close()
	}
}

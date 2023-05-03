// Copyright 2021-2023 The Inspektor Gadget authors
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
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	socketcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tcpbits"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang iterSockets ./bpf/sockets.c -- -I../../../../${TARGET} -I ../../../common/ -Werror -O2 -g -c -x c

type Tracer struct {
	iter       *link.Iter
	MountnsMap *ebpf.Map

	protocols    socketcollectortypes.Proto
	eventHandler func([]*socketcollectortypes.Event)
}

func parseIPv4(ipU32 uint32) string {
	ipBytes := make([]byte, 4)

	// net.IP() expects network byte order and parseIPv4 receives an
	// argument in host byte order, so it needs to be converted first
	binary.BigEndian.PutUint32(ipBytes, ipU32)
	ip := net.IP(ipBytes)

	return ip.String()
}

// Format from socket_bpf_seq_print() in bpf/socket_common.h
func parseStatus(proto string, statusUint uint8) (string, error) {
	status := tcpbits.TCPState(statusUint)

	// Transform TCP status into something more suitable for UDP
	if proto == "UDP" {
		switch status {
		case "ESTABLISHED":
			status = "ACTIVE"
		case "CLOSE":
			status = "INACTIVE"
		default:
			return "", fmt.Errorf("unexpected %s status %s", proto, status)
		}
	}

	return status, nil
}

func (t *Tracer) loadIter() error {
	spec, err := loadIterSockets()
	if err != nil {
		return fmt.Errorf("load sockets BPF programs: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements[gadgets.MntNsFilterMapName] = t.MountnsMap
	}

	consts := map[string]interface{}{
		"skip_tcp":                t.protocols != socketcollectortypes.ALL && t.protocols != socketcollectortypes.TCP,
		"skip_udp":                t.protocols != socketcollectortypes.ALL && t.protocols != socketcollectortypes.UDP,
		gadgets.FilterByMntNsName: filterByMntNs,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("RewriteConstants: %w", err)
	}

	kallsyms.SpecUpdateAddresses(spec, []string{"socket_file_ops"})

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	objs := &iterSocketsObjects{}
	if err := spec.LoadAndAssign(objs, &opts); err != nil {
		var errVerifier *ebpf.VerifierError
		if errors.As(err, &errVerifier) {
			fmt.Printf("Error: %+v\n", errVerifier)
		}
		return fmt.Errorf("load sockets BPF iterator: %w", err)
	}
	defer objs.Close()

	t.iter, err = link.AttachIter(link.IterOptions{
		Program: objs.IgSocketsIt,
	})
	if err != nil {
		return fmt.Errorf("attach sockets BPF iterator: %w", err)
	}

	return nil
}

// RunCollector is currently exported so it can be called from Collect()
func (t *Tracer) RunCollector() ([]*socketcollectortypes.Event, error) {
	sockets := []*socketcollectortypes.Event{}

	type socketKey struct {
		proto string
		netns uint32
		inode uint64
	}
	seenSocket := map[socketKey]bool{}

	reader, err := t.iter.Open()
	if err != nil {
		return nil, fmt.Errorf("open BPF iterator: %w", err)
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var status, proto string
		var ipversion int
		var destp, srcp uint16
		var dest, src string
		var hexStatus uint8
		var inodeNumber uint64
		var mntns uint64
		var netns uint32
		var command string
		var pid, parentPid int
		var uid, gid uint32

		// Format from socket_bpf_seq_print() in bpf/socket_common.h
		// IP addresses and ports are in host-byte order
		text := scanner.Text()
		matchedElems, err := fmt.Sscanf(text, "%s %d %s %s %04X %04X %02X %d %d %d %d %d %d %d",
			&proto, &ipversion,
			&src, &dest, &srcp, &destp,
			&hexStatus, &inodeNumber, &netns, &mntns,
			&parentPid, &pid, &uid, &gid)
		if err != nil {
			return nil, fmt.Errorf("parse sockets information: %w", err)
		}
		if matchedElems != 14 {
			return nil, fmt.Errorf("parse sockets information: found %d fields", matchedElems)
		}
		textSplit := strings.SplitN(text, " ", 15)
		if len(textSplit) != 15 {
			return nil, fmt.Errorf("failed to parse process information, expected 15 matched elements had %d", len(textSplit))
		}
		command = textSplit[14]

		status, err = parseStatus(proto, hexStatus)
		if err != nil {
			return nil, err
		}

		// If two processes share the same file descriptor table (see CLONE_FILES in man 2 clone),
		// the same socket will be seen twice. This is the case with nginx worker processes.
		// Skip sockets that have already been seen.
		key := socketKey{proto, netns, inodeNumber}
		if seenSocket[key] {
			continue
		}
		seenSocket[key] = true

		sockets = append(sockets, &socketcollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: mntns},
			WithNetNsID:   eventtypes.WithNetNsID{NetNsID: uint64(netns)},
			Pid:           pid,
			Uid:           uid,
			Gid:           gid,
			Command:       command,
			ParentPid:     parentPid,
			Protocol:      proto,
			IPVersion:     ipversion,
			LocalAddress:  net.ParseIP(src).String(),
			LocalPort:     srcp,
			RemoteAddress: net.ParseIP(dest).String(),
			RemotePort:    destp,
			Status:        status,
			InodeNumber:   inodeNumber,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading output of BPF iterator: %w", err)
	}

	return sockets, nil
}

// ---

func NewTracer(protocols socketcollectortypes.Proto) (*Tracer, error) {
	tracer := &Tracer{
		protocols: protocols,
	}

	if err := tracer.loadIter(); err != nil {
		tracer.CloseIter()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return tracer, nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*socketcollectortypes.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
}

// CloseIter is currently exported so it can be called from Collect()
func (t *Tracer) CloseIter() {
	if t.iter != nil {
		t.iter.Close()
	}
	t.iter = nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	protocols := gadgetCtx.GadgetParams().Get(ParamProto).AsString()
	t.protocols, _ = socketcollectortypes.ProtocolsMap[protocols]

	defer t.CloseIter()
	if err := t.loadIter(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	allSockets := []*socketcollectortypes.Event{}
	// TODO: Remove podname, namespace and node arguments from RunCollector.
	// The enrichment will be done in the event handler. In addition, pass
	// the netns to avoid retrieving it again in RunCollector.
	sockets, err := t.RunCollector()
	if err != nil {
		return fmt.Errorf("read sockets: %w", err)
	}
	allSockets = append(allSockets, sockets...)

	t.eventHandler(allSockets)
	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.MountnsMap = mountnsMap
}

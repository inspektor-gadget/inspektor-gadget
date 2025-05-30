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
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketenricher ./bpf/socket-enricher.bpf.c -- -I./bpf/

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketsiter ./bpf/sockets-iter.bpf.c -- -I./bpf/

const (
	SocketsMapName   = "gadget_sockets"
	SocketsValueName = "sockets_value"
)

// SocketEnricher creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code in the dns and
// sni gadgets.
type SocketEnricher struct {
	objs     socketenricherObjects
	objsIter socketsiterObjects
	links    []link.Link

	closeOnce sync.Once
	done      chan bool
	config    Config

	valueBtfSpec   *btf.Spec
	valueBtfStruct *btf.Struct
}

func (se *SocketEnricher) SocketsMap() *ebpf.Map {
	return se.objs.GadgetSockets
}

type Config struct {
	EnabledFields []string
}

func NewSocketEnricher(config Config) (*SocketEnricher, error) {
	se := &SocketEnricher{
		config: config,
	}

	if err := se.start(); err != nil {
		se.Close()
		return nil, err
	}

	return se, nil
}

// ValueBtf returns the BTF struct for the sockets_val structure
func (se *SocketEnricher) ValueBtf() (*btf.Spec, *btf.Struct, error) {
	return se.valueBtfSpec, se.valueBtfStruct, nil
}

func (se *SocketEnricher) generateValueBtf() error {
	// register some common types
	uint8T := btfhelpers.BtfInt(8, btf.Unsigned)
	uint16T := btfhelpers.BtfInt(16, btf.Unsigned)
	uint32T := btfhelpers.BtfInt(32, btf.Unsigned)
	uint64T := btfhelpers.BtfInt(64, btf.Unsigned)
	int8T := btfhelpers.BtfInt(8, btf.Signed)
	int16T := btfhelpers.BtfInt(16, btf.Signed)
	int32T := btfhelpers.BtfInt(32, btf.Signed)
	int64T := btfhelpers.BtfInt(64, btf.Signed)
	charT := btfhelpers.BtfInt(8, btf.Signed)
	cString16 := btfhelpers.BtfArray(uint32T, charT, 16)
	cString512 := btfhelpers.BtfArray(uint32T, charT, 512)

	types := []btf.Type{
		uint8T, uint16T, uint32T, uint64T,
		int8T, int16T, int32T, int64T,
		charT, cString16, cString512,
	}

	// fixed fields. This needs to be aligned with the definition of sockets_val
	// in include/gadget/types.h
	members := []btf.Member{
		{
			Name:   "mntns",
			Type:   uint64T,
			Offset: btf.Bits(0 * 8),
		},
		{
			Name:   "pid_tgid",
			Type:   uint64T,
			Offset: btf.Bits(8 * 8),
		},
		{
			Name:   "uid_gid",
			Type:   uint64T,
			Offset: btf.Bits(16 * 8),
		},
		{
			Name:   "ptask",
			Type:   cString16,
			Offset: btf.Bits(24 * 8),
		},
		{
			Name:   "task",
			Type:   cString16,
			Offset: btf.Bits(40 * 8),
		},
		{
			Name:   "sock",
			Type:   uint64T,
			Offset: btf.Bits(56 * 8),
		},
		{
			Name:   "deletion_timestamp",
			Type:   uint64T,
			Offset: btf.Bits(64 * 8),
		},
		{
			Name:   "ppid",
			Type:   uint32T,
			Offset: btf.Bits(72 * 8),
		},
		{
			Name:   "ipv6only",
			Type:   charT,
			Offset: btf.Bits(76 * 8),
		},
	}

	optionalFields := []struct {
		name string
		size uint32
		typ  btf.Type
	}{
		{
			name: "cwd",
			size: 512,
			typ:  cString512,
		},
		{
			name: "exepath",
			size: 512,
			typ:  cString512,
		},
	}

	// start with the offset of the first optional field, cwd.
	currentOffset := uint32(80)

	// Add optional fields if they are enabled in the config.
	for _, field := range optionalFields {
		if !slices.Contains(se.config.EnabledFields, field.name) {
			continue
		}
		member := btf.Member{
			Name:   field.name,
			Type:   field.typ,
			Offset: btf.Bits(currentOffset * 8),
		}
		members = append(members, member)
		currentOffset += field.size
	}

	btfStruct := &btf.Struct{
		Name:    SocketsValueName,
		Size:    currentOffset,
		Members: members,
	}
	types = append(types, btfStruct)

	btfSpec, err := btfhelpers.BuildBTFSpec(types)
	if err != nil {
		return err
	}

	se.valueBtfSpec = btfSpec
	se.valueBtfStruct = btfStruct

	return nil
}

func (se *SocketEnricher) start() error {
	specIter, err := loadSocketsiter()
	if err != nil {
		return fmt.Errorf("loading socketsiter asset: %w", err)
	}

	err = kallsyms.SpecUpdateAddresses(specIter, []string{"socket_file_ops"})
	if err != nil {
		// Being unable to access to /proc/kallsyms can be caused by not having
		// CAP_SYSLOG.
		log.Warnf("updating socket_file_ops address with ksyms: %v\nEither you cannot access /proc/kallsyms or this file does not contain socket_file_ops", err)
	}

	spec, err := loadSocketenricher()
	if err != nil {
		return fmt.Errorf("loading socket enricher asset: %w", err)
	}

	if err := se.generateValueBtf(); err != nil {
		return fmt.Errorf("getting BTF spec: %w", err)
	}

	kernelSpec := btfgen.GetBTFSpec()
	if kernelSpec == nil {
		kernelSpec, err = btf.LoadKernelSpec()
		if err != nil {
			return fmt.Errorf("loading kernel BTF spec: %w", err)
		}
	}

	mergedBtf, err := btfhelpers.MergeBtfs(kernelSpec, se.valueBtfSpec)
	if err != nil {
		return fmt.Errorf("merging BTF specs: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: mergedBtf,
		},
	}

	// update size of the sockets_map according to the fields configured by the
	// user. This works because CO-RE ensures programs will access the optional
	// fields at the right offset in this structure.
	mapSpecIter := specIter.Maps[SocketsMapName]
	mapSpecIter.ValueSize = se.valueBtfStruct.Size
	mapSpec := spec.Maps[SocketsMapName]
	mapSpec.ValueSize = se.valueBtfStruct.Size
	// TODO: This causes an error while loading it, probably the BTF we're genering is to totally right
	// mapSpec.Value = btfStruct

	disableBPFIterators := false
	if err := specIter.LoadAndAssign(&se.objsIter, &opts); err != nil {
		disableBPFIterators = true
		log.Warnf("Socket enricher: skip loading iterators: %v", err)
	}

	if disableBPFIterators {
		socketSpec := &socketenricherSpecs{}
		if err := spec.Assign(socketSpec); err != nil {
			return err
		}
		if err := socketSpec.DisableBpfIterators.Set(true); err != nil {
			return err
		}
	} else {
		opts.MapReplacements = map[string]*ebpf.Map{
			SocketsMapName: se.objsIter.GadgetSockets,
		}
	}

	if err := spec.LoadAndAssign(&se.objs, &opts); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	var l link.Link

	// bind
	l, err = link.Kprobe("inet_bind", se.objs.IgBindIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet_bind", se.objs.IgBindIpv4X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_bind", se.objs.IgBindIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet6_bind", se.objs.IgBindIpv6X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// connect
	l, err = link.Kprobe("tcp_connect", se.objs.IgTcpCoE, nil)
	if err != nil {
		return fmt.Errorf("attaching connect kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_connect", se.objs.IgTcpCoX, nil)
	if err != nil {
		return fmt.Errorf("attaching connect kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// udp_sendmsg
	l, err = link.Kprobe("udp_sendmsg", se.objs.IgUdpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_sendmsg ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("udpv6_sendmsg", se.objs.IgUdp6Sendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching udpv6_sendmsg ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	// release
	l, err = link.Kprobe("inet_release", se.objs.IgFreeIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_release", se.objs.IgFreeIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	if !disableBPFIterators {
		// get initial sockets
		socketsIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSocketsIt,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator: %w", err)
		}
		defer socketsIter.Close()

		_, err = bpfiterns.Read(socketsIter)
		if err != nil {
			return fmt.Errorf("read BPF iterator: %w", err)
		}

		// Schedule socket cleanup
		cleanupIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSkCleanup,
			Map:     se.objsIter.GadgetSockets,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator for cleanups: %w", err)
		}
		se.links = append(se.links, cleanupIter)

		se.done = make(chan bool)
		go se.cleanupDeletedSockets(cleanupIter)
	}

	return nil
}

func (se *SocketEnricher) cleanupDeletedSockets(cleanupIter *link.Iter) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-se.done:
			return
		case <-ticker.C:
			err := se.cleanupDeletedSocketsNow(cleanupIter)
			if err != nil {
				fmt.Printf("socket enricher: %v\n", err)
			}
		}
	}
}

func (se *SocketEnricher) cleanupDeletedSocketsNow(cleanupIter *link.Iter) error {
	// No need to change pidns for this iterator because cleanupIter is an
	// iterator on a map, not on tasks.
	_, err := bpfiterns.ReadOnCurrentPidNs(cleanupIter)
	return err
}

func (se *SocketEnricher) Close() {
	se.closeOnce.Do(func() {
		if se.done != nil {
			close(se.done)
		}
	})

	for _, l := range se.links {
		gadgets.CloseLink(l)
	}
	se.links = nil
	se.objs.Close()
	se.objsIter.Close()
}

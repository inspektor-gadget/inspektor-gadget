//go:build linux
// +build linux

// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this bio except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcptop/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// #include <linux/types.h>
// #include "./bpf/tcptop.h"
// #include <arpa/inet.h>
// #include <stdlib.h>
//
//char *string_ip(const void *addr, int ip_type) {
//	socklen_t size;
//	char *ip;
//
//  // Should not occur because eBPF code already filter on this.
//	if (ip_type != AF_INET && ip_type != AF_INET6)
//		return NULL;
//
//	size = sizeof(*ip) * INET6_ADDRSTRLEN;
//	ip = malloc(size);
//  if (ip == NULL)
//		return NULL;
//
//	inet_ntop(ip_type, addr, ip, size);
//
//	return ip;
//}
//
// char *dst_addr(struct ip_key_t *key) {
// 	return string_ip(&key->daddr, key->family);
// }
//
// char *src_addr(struct ip_key_t *key) {
// 	return string_ip(&key->saddr, key->family);
// }
import "C"

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang tcptop ./bpf/tcptop.bpf.c -- -I./bpf/ -I../../.. -target bpf -D__TARGET_ARCH_x86"

type Config struct {
	MountnsMap   *ebpf.Map
	TargetPid    int32
	TargetFamily int32
	MaxRows      int
	Interval     time.Duration
	SortBy       types.SortBy
	Node         string
}

type Tracer struct {
	config             *Config
	objs               tcptopObjects
	tcpSendmsgLink     link.Link
	tcpCleanupRbufLink link.Link
	resolver           containercollection.ContainerResolver
	statsCallback      func([]types.Stats)
	errorCallback      func(error)
	done               chan bool
}

func NewTracer(config *Config, resolver containercollection.ContainerResolver,
	statsCallback func([]types.Stats), errorCallback func(error),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		resolver:      resolver,
		statsCallback: statsCallback,
		errorCallback: errorCallback,
		done:          make(chan bool),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	close(t.done)

	t.tcpSendmsgLink = gadgets.CloseLink(t.tcpSendmsgLink)
	t.tcpCleanupRbufLink = gadgets.CloseLink(t.tcpCleanupRbufLink)

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadTcptop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
		"target_pid":       t.config.TargetPid,
		"target_family":    t.config.TargetFamily,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.tcpSendmsgLink, err = link.Kprobe("tcp_sendmsg", t.objs.TcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.tcpCleanupRbufLink, err = link.Kprobe("tcp_cleanup_rbuf", t.objs.TcpCleanupRbuf, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.run()

	return nil
}

func (t *Tracer) nextStats() ([]types.Stats, error) {
	stats := []types.Stats{}

	var prev *C.struct_ip_key_t = nil
	key := C.struct_ip_key_t{}
	ips := t.objs.IpMap

	defer func() {
		// delete elements
		err := ips.NextKey(nil, unsafe.Pointer(&key))
		if err != nil {
			return
		}

		for {
			if err := ips.Delete(key); err != nil {
				return
			}

			prev = &key
			if err := ips.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
				return
			}
		}
	}()

	// gather elements
	err := ips.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stats, nil
		}
		return nil, fmt.Errorf("error getting next key: %w", err)
	}

	for {
		val := C.struct_traffic_t{}
		if err := ips.Lookup(key, unsafe.Pointer(&val)); err != nil {
			return nil, err
		}

		srcAddr := C.src_addr(&key)
		dstAddr := C.dst_addr(&key)

		stat := types.Stats{
			Saddr:     C.GoString(srcAddr),
			Daddr:     C.GoString(dstAddr),
			MountNsID: uint64(key.mntnsid),
			Pid:       int32(key.pid),
			Comm:      C.GoString(&key.name[0]),
			Sport:     uint16(key.lport),
			Dport:     uint16(key.dport),
			Family:    uint16(key.family),
			Sent:      uint64(val.sent),
			Received:  uint64(val.received),
		}

		C.free(unsafe.Pointer(srcAddr))
		C.free(unsafe.Pointer(dstAddr))

		container := t.resolver.LookupContainerByMntns(stat.MountNsID)
		if container != nil {
			stat.Container = container.Name
			stat.Pod = container.Podname
			stat.Namespace = container.Namespace
			stat.Node = t.config.Node
		}

		stats = append(stats, stat)

		prev = &key
		if err := ips.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	types.SortStats(stats, t.config.SortBy)

	return stats, nil
}

func (t *Tracer) run() {
	ticker := time.NewTicker(t.config.Interval)

	go func() {
		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				stats, err := t.nextStats()
				if err != nil {
					t.errorCallback(err)
					return
				}

				n := len(stats)
				if n > t.config.MaxRows {
					n = t.config.MaxRows
				}
				t.statsCallback(stats[:n])
			}
		}
	}()
}

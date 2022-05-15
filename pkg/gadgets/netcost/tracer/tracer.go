// Copyright 2019-2022 The Inspektor Gadget authors
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

package tracer

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/inspektor-gadget/pkg/rawsock"
)

// #include "bpf/netcost.h"
import "C"

//go:generate sh -c "echo $CLANG_OS_FLAGS; GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang netcost ./bpf/netcost.c -- $CLANG_OS_FLAGS -I./bpf/ -target bpf -D__TARGET_ARCH_x86"

const (
	BPFProgName     = "bpf_prog1"
	BPFMapName      = "lpm_stats"
	BPFSocketAttach = 50
)

type cidrStats struct {
	BytesRecv   uint64 `json:"bytesRecv"`
	BytesSent   uint64 `json:"bytesSent"`
	PacketsRecv uint64 `json:"packetsRecv"`
	PacketsSent uint64 `json:"packetsSent"`
}

type link struct {
	collection    *ebpf.Collection
	lpmMap        *ebpf.Map
	networksStats map[string]*cidrStats

	sockFd int

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	mu sync.Mutex

	spec *ebpf.CollectionSpec

	// key: namespace/podname
	// value: link
	attachments map[string]*link

	node    string
	netList []net.IPNet

	// Prometheus counters
	bytesCounter   *prometheus.CounterVec
	packetsCounter *prometheus.CounterVec
}

func NewTracer(node string) (*Tracer, error) {
	spec, err := loadNetcost()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	bytesCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "netcost",
			Name:      "bytes",
			Help:      "Bytes on the network",
		}, []string{"node", "pod", "direction", "cidr"},
	)
	packetsCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "netcost",
			Name:      "packets",
			Help:      "Packets on the network",
		}, []string{"node", "pod", "direction", "cidr"},
	)

	go ListenAndServe("127.0.0.1:19100")

	var netList []net.IPNet
	netArr := strings.Split("1.1.1.1/32,10.0.0.0/8,0.0.0.0/0", ",")
	for _, n := range netArr {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			fmt.Printf("Skipping invalid IPNet %q: %s\n", n, err)
			continue
		}
		netList = append(netList, *ipnet)
	}

	t := &Tracer{
		spec:           spec,
		attachments:    make(map[string]*link),
		bytesCounter:   bytesCounter,
		packetsCounter: packetsCounter,
		netList:        netList,
		node:           node,
	}

	go t.updateAllMetrics()

	return t, nil
}

func ListenAndServe(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	server := &http.Server{Addr: addr, Handler: nil}

	err := server.ListenAndServe()
	if err != http.ErrServerClosed {
		log.Errorf("couldn't listen and serve Prometheus endpoint: %s", err)
	}
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
) error {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	coll, err := ebpf.NewCollectionWithOptions(t.spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSize: ebpf.DefaultVerifierLogSize * 100}})
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	prog, ok := coll.Programs[BPFProgName]
	if !ok {
		return fmt.Errorf("failed to find BPF program %q", BPFProgName)
	}

	lpmMap, ok := coll.Maps[BPFMapName]
	if !ok {
		return fmt.Errorf("failed to find BPF map %q", BPFMapName)
	}
	t.initLpmMap(lpmMap)

	sockFd, err := rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, BPFSocketAttach, prog.FD()); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	l := &link{
		collection:    coll,
		sockFd:        sockFd,
		users:         1,
		lpmMap:        lpmMap,
		networksStats: make(map[string]*cidrStats),
	}
	t.attachments[key] = l

	return nil
}

func (t *Tracer) initLpmMap(m *ebpf.Map) error {
	for _, n := range t.netList {
		ip := n.IP.To4()
		if ip == nil {
			// Only IPv4 is supported for now
			continue
		}
		siz, _ := n.Mask.Size()
		IPBigEndian := unsafe.Pointer(&ip[0])
		key := []uint32{uint32(siz), *(*uint32)(IPBigEndian)}
		value := C.struct_cidr_stats{}
		err := m.Put(unsafe.Pointer(&key[0]), unsafe.Pointer(&value))
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *Tracer) updateAllMetrics() {
	for {
		for key, l := range t.attachments {
			t.updateLinkMetrics(key, l)
		}
	}
}

func (t *Tracer) updateLinkMetrics(pod string, l *link) {
	var key [2]uint32
	var value C.struct_cidr_stats

	iter := l.lpmMap.Iterate()
	for iter.Next(&key, unsafe.Pointer(&value)) {
		ip := make(net.IP, 4)
		ipPtr := (uintptr)(unsafe.Pointer(&key[1]))
		for i := 0; i < 4; i++ {
			ip[i] = *(*byte)(unsafe.Pointer(ipPtr + uintptr(i)))
		}
		n := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(int(key[0]), 32),
		}
		network := n.String()
		if _, ok := l.networksStats[network]; !ok {
			l.networksStats[network] = &cidrStats{}
		}

		if l.networksStats[network].BytesRecv != uint64(value.bytes_recv) {
			inc := float64(uint64(value.bytes_recv) - l.networksStats[network].BytesRecv)
			t.bytesCounter.WithLabelValues(t.node, pod, "ingress", network).Add(inc)
			l.networksStats[network].BytesRecv = uint64(value.bytes_recv)
		}
		if l.networksStats[network].BytesSent != uint64(value.bytes_sent) {
			inc := float64(uint64(value.bytes_sent) - l.networksStats[network].BytesSent)
			t.bytesCounter.WithLabelValues(t.node, pod, "egress", network).Add(inc)
			l.networksStats[network].BytesSent = uint64(value.bytes_sent)
		}
		if l.networksStats[network].PacketsRecv != uint64(value.packets_recv) {
			inc := float64(uint64(value.packets_recv) - l.networksStats[network].PacketsRecv)
			t.packetsCounter.WithLabelValues(t.node, pod, "ingress", network).Add(inc)
			l.networksStats[network].PacketsRecv = uint64(value.packets_recv)
		}

		if l.networksStats[network].PacketsSent != uint64(value.packets_sent) {
			inc := float64(uint64(value.packets_sent) - l.networksStats[network].PacketsSent)
			t.packetsCounter.WithLabelValues(t.node, pod, "egress", network).Add(inc)
			l.networksStats[network].PacketsSent = uint64(value.packets_sent)
		}

	}
	if err := iter.Err(); err != nil {
		log.Errorf("failed to update metrics for pod %s: %s", pod, err)
	}
}

func (t *Tracer) releaseLink(key string, l *link) {
	unix.Close(l.sockFd)
	l.collection.Close()
	delete(t.attachments, key)
}

func (t *Tracer) Detach(key string) error {
	if l, ok := t.attachments[key]; ok {
		l.users--
		if l.users == 0 {
			t.releaseLink(key, l)
		}
		return nil
	} else {
		return fmt.Errorf("key not attached: %q", key)
	}
}

func (t *Tracer) Close() {
	for key, l := range t.attachments {
		t.releaseLink(key, l)
	}
}

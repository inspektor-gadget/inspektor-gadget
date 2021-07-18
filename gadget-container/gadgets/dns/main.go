// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	BPF_PROG_NAME = "bpf_prog1"
	SO_ATTACH_BPF = 50
)

var (
	networkNamespace = flag.String("n", "", "Path to a network namespace (e.g. /proc/42/ns/net)")
	networkInterface = flag.String("i", "", "Network interface to listen on")
)

func increaseRlimit() error {
	limit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit)
}

// Both openRawSock and htons are from github.com/cilium/ebpf:
// MIT License
// https://github.com/cilium/ebpf/blob/eaa1fe7482d837490c22d9d96a788f669b9e3843/example_sock_elf_test.go#L146-L166
func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func main() {
	flag.Parse()
	if err := increaseRlimit(); err != nil {
		log.Fatalf("Failed to increase memlock limit: %s", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		log.Fatalf("Failed to load asset: %s", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 64 * 1024 * 800,
		},
	})
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %s", err)
	}

	prog, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		log.Fatalf("Failed to find BPF program %q", BPF_PROG_NAME)
	}

	iface, err := net.InterfaceByName(*networkInterface)
	if err != nil {
		log.Fatalf("Failed to find network interface: %s", err)
	}
	sockFd, err := openRawSock(iface.Index)
	if err != nil {
		log.Fatalf("Failed to open raw socket: %s", err)
	}

	if err := syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		log.Fatalf("Failed to attach BPF program: %s", err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}

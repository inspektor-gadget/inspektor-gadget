// Copyright 2021 The Inspektor Gadget authors
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
// limitations under the License

package tracer

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"

	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	"github.com/kinvolk/inspektor-gadget/pkg/netnsenter"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang IterTCPv4 ./bpf/tcp4-collector.c -- -I../../../${TARGET} -Werror -O2 -g -c -x c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang IterUDPv4 ./bpf/udp4-collector.c -- -I../../../${TARGET} -Werror -O2 -g -c -x c

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
	statusMap := [...]string{
		"ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
		"LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}

	// Kernel enum starts from 1, adjust it to the statusMap
	if statusUint == 0 || len(statusMap) <= int(statusUint-1) {
		return "", fmt.Errorf("invalid %s status: %d", proto, statusUint)
	}
	status := statusMap[statusUint-1]

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

func getTCPIter() (*link.Iter, error) {
	objs := IterTCPv4Objects{}
	if err := LoadIterTCPv4Objects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load TCP BPF objects: %w", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTcp4,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach TCP BPF iterator: %w", err)
	}

	return it, nil
}

func getUDPIter() (*link.Iter, error) {
	objs := IterUDPv4Objects{}
	if err := LoadIterUDPv4Objects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load UDP BPF objects: %w", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpUdp4,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach UDP BPF iterator: %w", err)
	}

	return it, nil
}

func RunCollector(pid uint32, podname, namespace, node string, proto socketcollectortypes.Proto) ([]socketcollectortypes.Event, error) {
	var err error
	var it *link.Iter
	iters := []*link.Iter{}

	if proto == socketcollectortypes.TCP || proto == socketcollectortypes.ALL {
		it, err = getTCPIter()
		if err != nil {
			return nil, err
		}
		iters = append(iters, it)
	}

	if proto == socketcollectortypes.UDP || proto == socketcollectortypes.ALL {
		it, err = getUDPIter()
		if err != nil {
			return nil, err
		}
		iters = append(iters, it)
	}

	sockets := []socketcollectortypes.Event{}
	err = netnsenter.NetnsEnter(int(pid), func() error {
		for _, it := range iters {
			reader, err := it.Open()
			if err != nil {
				return fmt.Errorf("failed to open BPF iterator: %w", err)
			}
			defer reader.Close()

			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				var status, proto string
				var destp, srcp uint16
				var dest, src uint32
				var hexStatus uint8
				var inodeNumber uint64

				// Format from socket_bpf_seq_print() in bpf/socket_common.h
				// IP addresses and ports are in host-byte order
				len, err := fmt.Sscanf(scanner.Text(), "%s %08X %04X %08X %04X %02X %d",
					&proto, &src, &srcp, &dest, &destp, &hexStatus, &inodeNumber)
				if err != nil || len != 7 {
					return fmt.Errorf("failed to parse sockets information: %w", err)
				}

				status, err = parseStatus(proto, hexStatus)
				if err != nil {
					return err
				}

				sockets = append(sockets, socketcollectortypes.Event{
					Event: eventtypes.Event{
						Type:      eventtypes.NORMAL,
						Node:      node,
						Namespace: namespace,
						Pod:       podname,
					},
					Protocol:      proto,
					LocalAddress:  parseIPv4(src),
					LocalPort:     srcp,
					RemoteAddress: parseIPv4(dest),
					RemotePort:    destp,
					Status:        status,
					InodeNumber:   inodeNumber,
				})
			}

			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed reading output of BPF iterator: %w", err)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return sockets, nil
}

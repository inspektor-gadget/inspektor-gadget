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

package rawsock

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netns"
)

// Both openRawSock and htons are from github.com/cilium/ebpf:
// MIT License
// https://github.com/cilium/ebpf/blob/eaa1fe7482d837490c22d9d96a788f669b9e3843/example_sock_elf_test.go#L146-L166

// htons converts an unsigned short integer from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// OpenRawSock opens a raw socket in the network namespace used by the pid
// passed as parameter.
// Returns the sock fd and an error.
func OpenRawSock(pid uint32) (int, error) {
	if pid != 0 {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Save the current network namespace
		origns, _ := netns.Get()
		defer origns.Close()

		netnsHandle, err := netns.GetFromPid(int(pid))
		if err != nil {
			return -1, err
		}
		defer netnsHandle.Close()
		err = netns.Set(netnsHandle)
		if err != nil {
			return -1, err
		}

		// Switch back to the original namespace
		defer netns.Set(origns)
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  0, // 0 matches any interface
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return -1, err
	}
	return sock, nil
}

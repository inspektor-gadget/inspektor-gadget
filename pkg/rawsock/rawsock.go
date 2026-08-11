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
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	netnsig "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/netns"
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
// passed as parameter. A pid of 0 means the current network namespace.
// Returns the sock fd and an error.
func OpenRawSock(pid uint32) (int, error) {
	if pid == 0 {
		return openRawSock()
	}

	netnsHandle, err := netnsig.GetFromPidWithAltProcfs(int(pid), host.HostProcFs)
	if err != nil {
		return -1, err
	}
	defer netnsHandle.Close()

	return OpenRawSockInNetns(netnsHandle)
}

// OpenNetnsPath opens the network namespace referred to by the given filesystem
// path, e.g. a bind mount created by "ip netns add" (/run/netns/<name>) or a
// procfs namespace link (/proc/<pid>/ns/net). It returns a handle to it
// together with its inode number, both derived from the same file descriptor,
// so that the namespace the inode identifies is necessarily the one the handle
// refers to even if the path is replaced afterwards. The caller owns the handle
// and must close it.
//
// The path is verified to live on nsfs: callers key attachments by inode, and
// inode numbers are only comparable with the ones taken from /proc/<pid>/ns/net
// within that filesystem. Without the check, an unrelated file could alias an
// existing attachment.
func OpenNetnsPath(path string) (netns.NsHandle, uint64, error) {
	// netns.GetFromPath() opens the path; the resulting handle is only usable
	// with setns(2) if it really refers to a network namespace, which
	// OpenRawSockInNetns() relies on the kernel to enforce. The checks below
	// are what makes the failure diagnosable, and the inode trustworthy.
	netnsHandle, err := netns.GetFromPath(path)
	if err != nil {
		return netns.None(), 0, fmt.Errorf("getting network namespace from path %q: %w", path, err)
	}

	inode, err := netnsInode(int(netnsHandle), path)
	if err != nil {
		netnsHandle.Close()
		return netns.None(), 0, err
	}

	return netnsHandle, inode, nil
}

// netnsInode returns the inode number of the namespace the given file
// descriptor refers to, after checking that it lives on nsfs. path is only used
// for error messages.
func netnsInode(fd int, path string) (uint64, error) {
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil {
		return 0, fmt.Errorf("statfs %q: %w", path, err)
	}
	if statfs.Type != unix.NSFS_MAGIC {
		return 0, fmt.Errorf("%q does not refer to a namespace", path)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, fmt.Errorf("stat %q: %w", path, err)
	}
	return stat.Ino, nil
}

// OpenRawSockInNetns opens a raw socket in the network namespace referred to by
// the given handle, restoring the calling thread's original network namespace
// before returning. Returns the sock fd and an error.
func OpenRawSockInNetns(netnsHandle netns.NsHandle) (sock int, err error) {
	sock = -1

	// Lock the OS thread: setns(2) affects the calling thread only, so the
	// goroutine must not be migrated to another thread while we are in the
	// target network namespace.
	runtime.LockOSThread()
	unlockOSThread := true
	defer func() {
		if unlockOSThread {
			runtime.UnlockOSThread()
		}
	}()

	origns, err := netns.Get()
	if err != nil {
		return -1, fmt.Errorf("getting current network namespace: %w", err)
	}
	defer origns.Close()

	if err := netns.Set(netnsHandle); err != nil {
		return -1, fmt.Errorf("entering network namespace: %w", err)
	}
	defer func() {
		if restoreErr := netns.Set(origns); restoreErr != nil {
			// The thread is stuck in the wrong network namespace. Leave it
			// locked to this goroutine so the Go runtime never hands it to
			// another one: the thread is destroyed when the goroutine exits.
			// Unlocking here would silently taint unrelated code.
			// See https://github.com/inspektor-gadget/inspektor-gadget/issues/5439
			unlockOSThread = false

			// The socket, if any, was opened in the wrong namespace from the
			// caller's point of view; do not hand back a fd we cannot vouch for.
			if sock != -1 {
				syscall.Close(sock)
				sock = -1
			}
			err = errors.Join(err, fmt.Errorf("restoring network namespace: %w", restoreErr))
		}
	}()

	return openRawSock()
}

// openRawSock opens a raw socket in the current network namespace.
func openRawSock() (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  0, // 0 matches any interface
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		syscall.Close(sock)
		return -1, err
	}
	return sock, nil
}

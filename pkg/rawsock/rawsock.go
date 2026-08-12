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
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"unsafe"

	pathrs "github.com/cyphar/filepath-securejoin/pathrs-lite"
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
// The path is provided by the user and interpreted inside the host filesystem,
// which is mounted elsewhere when running in a container, so it is confined to
// host.HostRoot: no symlink along the way may escape it.
//
// The path is verified to live on nsfs: callers key attachments by inode, and
// inode numbers are only comparable with the ones taken from /proc/<pid>/ns/net
// within that filesystem. Without the check, an unrelated file could alias an
// existing attachment.
func OpenNetnsPath(path string) (netns.NsHandle, uint64, error) {
	if isProcfsPath(path) {
		return openProcfsNetnsPath(path)
	}
	return openConfinedNetnsPath(path)
}

// openConfinedNetnsPath resolves path below the host root and opens it as a
// single operation.
//
// Resolving to a path string first and opening it afterwards - what
// securejoin.SecureJoin() does - would only be safe at the instant the string
// is returned: an attacker able to write to a directory along the way can
// replace a component with a symlink before the open and redirect it out of the
// host root. pathrs resolves and opens in one step, with
// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS) where the kernel supports it,
// so there is no window. RESOLVE_IN_ROOT is what confines the resolution;
// refusing to traverse magic links is RESOLVE_NO_MAGICLINKS, which pathrs sets
// as well.
func openConfinedNetnsPath(path string) (netns.NsHandle, uint64, error) {
	// The handle is O_PATH, which is enough for the checks below and, unlike a
	// real open, has no side effects on whatever the path turned out to refer
	// to: opening a FIFO blocks until a writer appears, and some device nodes
	// act on open.
	pathHandle, err := pathrs.OpenInRoot(host.HostRoot, path)
	if err != nil {
		return netns.None(), 0, fmt.Errorf("resolving %q below host root %q: %w", path, host.HostRoot, err)
	}
	defer pathHandle.Close()

	// Refuse anything that is not a namespace before reopening it for real.
	if err := checkNsfs(int(pathHandle.Fd()), path); err != nil {
		return netns.None(), 0, err
	}

	// setns(2) rejects an O_PATH descriptor, so the handle has to be upgraded.
	// Reopening goes through /proc/thread-self/fd/<n>, which the kernel
	// resolves to the descriptor itself rather than walking the original path
	// again, so it lands on the file that was just checked and not on a
	// replacement. It does mean procfs has to be mounted for this to work.
	file, err := pathrs.Reopen(pathHandle, unix.O_RDONLY)
	if err != nil {
		return netns.None(), 0, fmt.Errorf("reopening %q: %w", path, err)
	}

	// netns.NsHandle takes over from the os.File here: duplicate the
	// descriptor, then close the original, so the two never own the same one.
	// F_DUPFD_CLOEXEC rather than dup(2), which does not copy the close-on-exec
	// flag - a namespace descriptor surviving into an exec'd child would hand
	// it a namespace it was never given.
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	file.Close()
	if err != nil {
		return netns.None(), 0, fmt.Errorf("duplicating descriptor for %q: %w", path, err)
	}
	netnsHandle := netns.NsHandle(fd)

	inode, err := netnsInode(fd, path)
	if err != nil {
		netnsHandle.Close()
		return netns.None(), 0, err
	}

	return netnsHandle, inode, nil
}

// openProcfsNetnsPath opens a namespace link below /proc.
//
// A link such as /proc/<pid>/ns/net is a magic link, which no userspace path
// resolution can follow: securejoin turns it into the literal string
// "net:[4026531840]", and openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)
// refuses to traverse it at all. Only the directory can be resolved; the last
// component is left to the kernel, which resolves it on open.
//
// Leaving a component unresolved is only safe because of what the two checks
// here establish. isProcfsPath() admits nothing but the exact shape of a
// namespace link, so the unresolved component is always a name procfs itself
// provides; and the directory holding it is required to be on procfs, so those
// names are the kernel's and not an attacker's. Without the second check, a
// directory an attacker can write to below <host root>/proc would do, since
// the last component is opened following symlinks. Every other path is
// confined by openConfinedNetnsPath().
//
// The directory is resolved once, to a descriptor, and everything afterwards
// goes through it: the check that it is procfs and the open of the last
// component are the same inode by construction. Resolving it to a string,
// checking that, and opening the string again would leave the directory free
// to be replaced in between - the same flaw as resolving and opening a path in
// two steps, one component further along.
func openProcfsNetnsPath(path string) (netns.NsHandle, uint64, error) {
	dir, base := filepath.Split(path)
	if base == "" {
		return netns.None(), 0, fmt.Errorf("%q must point at a network namespace", path)
	}

	// Confined like any other path: only the last component needs the kernel.
	dirHandle, err := pathrs.OpenInRoot(host.HostRoot, dir)
	if err != nil {
		return netns.None(), 0, fmt.Errorf("resolving %q below host root %q: %w", path, host.HostRoot, err)
	}
	defer dirHandle.Close()

	// The magic-link carve-out is only justified while the directory really is
	// procfs. Anything else reaching this far is refused rather than opened.
	if err := checkProcfs(int(dirHandle.Fd()), path); err != nil {
		return netns.None(), 0, err
	}

	// The kernel resolves the magic link on open. Relative to the descriptor
	// just checked, so it is that directory's entry and not one belonging to
	// something that replaced it. O_PATH is not an option here, unlike in the
	// confined case: setns(2) rejects it, and there is nothing to reopen
	// through, since re-resolving is what this avoids.
	//
	// The resulting handle is only usable with setns(2) if it really refers to
	// a network namespace, which OpenRawSockInNetns() relies on the kernel to
	// enforce. The check below is what makes the failure diagnosable, and the
	// inode trustworthy.
	fd, err := unix.Openat(int(dirHandle.Fd()), base, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return netns.None(), 0, fmt.Errorf("getting network namespace from path %q: %w", path, err)
	}
	netnsHandle := netns.NsHandle(fd)

	inode, err := netnsInode(fd, path)
	if err != nil {
		netnsHandle.Close()
		return netns.None(), 0, err
	}

	return netnsHandle, inode, nil
}

// procfsNetnsLink matches the paths a namespace magic link can have, and
// nothing else. "self" and "thread-self" are included because they are names
// procfs provides just as much as the numeric ones are, and refusing them
// would send a legitimate path to a resolution that cannot follow it.
var procfsNetnsLink = regexp.MustCompile(`^/proc/(?:\d+|self|thread-self)(?:/task/\d+)?/ns/[a-z_]+$`)

// isProcfsPath reports whether path is a procfs namespace link, whose last
// component is a magic link that only the kernel can resolve.
//
// The predicate is deliberately no wider than that. It used to admit anything
// below /proc, which handed the unconfined open of the last component to every
// path a caller could spell that way: an ordinary symlink at
// <host root>/proc/<anything>/<name> was followed straight out of the host
// root. Only the namespace links need the carve-out, so only they get it, and
// everything else is confined.
func isProcfsPath(path string) bool {
	return procfsNetnsLink.MatchString(filepath.Clean(path))
}

// checkProcfs returns an error unless the given file descriptor refers to a
// directory on procfs. path is only used for error messages.
func checkProcfs(fd int, path string) error {
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil {
		return fmt.Errorf("statfs %q: %w", path, err)
	}
	if statfs.Type != unix.PROC_SUPER_MAGIC {
		return fmt.Errorf("%q is not on procfs", path)
	}
	return nil
}

// checkNsfs returns an error unless the given file descriptor refers to a file
// on nsfs. path is only used for error messages.
func checkNsfs(fd int, path string) error {
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil {
		return fmt.Errorf("statfs %q: %w", path, err)
	}
	if statfs.Type != unix.NSFS_MAGIC {
		return fmt.Errorf("%q does not refer to a namespace", path)
	}
	return nil
}

// netnsInode returns the inode number of the namespace the given file
// descriptor refers to, after checking that it lives on nsfs. path is only used
// for error messages.
func netnsInode(fd int, path string) (uint64, error) {
	if err := checkNsfs(fd, path); err != nil {
		return 0, err
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

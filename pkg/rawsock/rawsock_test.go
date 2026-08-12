//go:build linux
// +build linux

// Copyright 2026 The Inspektor Gadget authors
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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// createTestNetns creates a fresh network namespace and returns a filesystem
// path referring to it. The namespace is kept alive by a dedicated thread
// until the test finishes.
func createTestNetns(t *testing.T) string {
	t.Helper()

	pathCh := make(chan string)
	errCh := make(chan error, 1)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	go func() {
		// The thread is deliberately never unlocked: unshare(CLONE_NEWNET)
		// is not reversible, so the thread must die with this goroutine
		// instead of being reused by the runtime.
		runtime.LockOSThread()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
			return
		}

		pathCh <- fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())

		// Hold the namespace open until the test is done with it.
		<-done
	}()

	select {
	case err := <-errCh:
		t.Fatalf("creating test network namespace: %s", err)
		return ""
	case path := <-pathCh:
		return path
	}
}

// statInode returns the inode of the path.
func statInode(t *testing.T, path string) uint64 {
	t.Helper()

	var stat unix.Stat_t
	require.NoError(t, unix.Stat(path, &stat), "stat %q", path)
	return stat.Ino
}

// currentThreadNetnsInode returns the network namespace inode of the calling
// thread. Callers must have the goroutine locked to its OS thread for the
// result to be meaningful.
func currentThreadNetnsInode(t *testing.T) uint64 {
	t.Helper()

	return statInode(t, fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid()))
}

// openRawSockAtPath composes OpenNetnsPath() and OpenRawSockInNetns() the way
// networktracer does, and returns the socket together with the namespace inode
// the two of them agreed on.
func openRawSockAtPath(path string) (int, uint64, error) {
	handle, inode, err := OpenNetnsPath(path)
	if err != nil {
		return -1, 0, err
	}
	defer handle.Close()

	sock, err := OpenRawSockInNetns(handle)
	if err != nil {
		return -1, 0, err
	}
	return sock, inode, nil
}

// requireRawSocket asserts that fd is a usable AF_PACKET raw socket.
func requireRawSocket(t *testing.T, fd int) {
	t.Helper()

	require.GreaterOrEqual(t, fd, 0, "expected a valid file descriptor")

	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	require.NoError(t, err, "getsockopt(SO_DOMAIN) on returned fd")
	require.Equal(t, unix.AF_PACKET, domain, "socket domain")

	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	require.NoError(t, err, "getsockopt(SO_TYPE) on returned fd")
	require.Equal(t, unix.SOCK_RAW, typ, "socket type")
}

func TestOpenRawSockCurrentNetns(t *testing.T) {
	utilstest.RequireRoot(t)

	// pid 0 means "do not switch namespace".
	fd, err := OpenRawSock(0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })

	requireRawSocket(t, fd)
}

func TestOpenRawSockNetnsPath(t *testing.T) {
	utilstest.RequireRoot(t)

	path := createTestNetns(t)

	// Pin the test goroutine so the "namespace restored" assertion below
	// observes the same thread that OpenRawSockInNetns switched.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	before := currentThreadNetnsInode(t)
	target := statInode(t, path)
	require.NotEqual(t, before, target, "test netns should differ from the current one")

	fd, inode, err := openRawSockAtPath(path)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })

	requireRawSocket(t, fd)
	require.Equal(t, target, inode, "OpenNetnsPath must report the namespace the path refers to")

	after := currentThreadNetnsInode(t)
	require.Equal(t, before, after, "calling thread's network namespace must be restored")
}

// TestOpenRawSockNetnsPathTwice checks that repeated calls each return an
// independent socket and keep leaving the calling thread where it was.
func TestOpenRawSockNetnsPathTwice(t *testing.T) {
	utilstest.RequireRoot(t)

	path := createTestNetns(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	before := currentThreadNetnsInode(t)

	fd1, inode1, err := openRawSockAtPath(path)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd1) })

	fd2, inode2, err := openRawSockAtPath(path)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd2) })

	require.NotEqual(t, fd1, fd2, "each call must return its own socket")
	require.Equal(t, inode1, inode2, "the same path must resolve to the same namespace")
	requireRawSocket(t, fd1)
	requireRawSocket(t, fd2)

	require.Equal(t, before, currentThreadNetnsInode(t), "calling thread's network namespace must be restored")
}

func TestOpenNetnsPathErrors(t *testing.T) {
	utilstest.RequireRoot(t)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "nonexistent path",
			path: "/run/netns/does-not-exist-4f2c1b",
		},
		{
			name: "not a network namespace",
			path: "/etc/hostname",
		},
		{
			name: "directory",
			path: "/tmp",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			before := currentThreadNetnsInode(t)

			fd, _, err := openRawSockAtPath(test.path)
			require.Error(t, err, "expected an error for path %q", test.path)
			require.Equal(t, -1, fd, "no file descriptor must be returned on error")
			require.Contains(t, err.Error(), test.path, "error must mention the offending path")

			require.Equal(t, before, currentThreadNetnsInode(t),
				"calling thread's network namespace must be unchanged after a failure")
		})
	}
}

// TestOpenNetnsPathConfinesToHostRoot checks that the path is interpreted
// inside the host root: a symlink may point anywhere below it, but nothing may
// leave it. Only the rejection is exercised, which needs no privileges.
func TestOpenNetnsPathConfinesToHostRoot(t *testing.T) {
	hostRoot := t.TempDir()

	saved := host.HostRoot
	host.HostRoot = hostRoot
	t.Cleanup(func() { host.HostRoot = saved })

	require.NoError(t, os.MkdirAll(filepath.Join(hostRoot, "run", "netns"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(hostRoot, "run", "inside"), []byte("x"), 0o644))

	// Points at a real network namespace on the host, which must be read as
	// <hostRoot>/proc/self/ns/net and so must not resolve.
	require.NoError(t, os.Symlink("/proc/self/ns/net", filepath.Join(hostRoot, "run", "netns", "escape")))
	// Stays below the host root and must be followed, failing on the nsfs check
	// rather than on resolution.
	require.NoError(t, os.Symlink("/run/inside", filepath.Join(hostRoot, "run", "netns", "inside")))

	t.Run("symlink out of the host root", func(t *testing.T) {
		handle, _, err := OpenNetnsPath("/run/netns/escape")
		require.Error(t, err, "a symlink pointing out of the host root must not resolve")
		require.Equal(t, -1, int(handle), "no file descriptor must be returned on error")
		require.NotContains(t, err.Error(), "does not refer to a namespace",
			"the path must be refused before it is opened, not after")
	})

	t.Run("symlink inside the host root", func(t *testing.T) {
		handle, _, err := OpenNetnsPath("/run/netns/inside")
		require.Error(t, err)
		require.Equal(t, -1, int(handle), "no file descriptor must be returned on error")
		require.Contains(t, err.Error(), "does not refer to a namespace",
			"a symlink below the host root must be followed, then rejected on its own merits")
	})
}

// TestOpenNetnsPathProcfsCarveOutIsNarrow checks the one place where a path
// component is left for the kernel to resolve.
//
// A namespace link is a magic link, so its last component cannot be resolved
// in userspace and is opened as it was given. That carve-out has to be exactly
// as wide as the thing that justifies it: while it applied to every path below
// /proc, an ordinary symlink in that position was followed straight out of the
// host root, and only the nsfs check afterwards stood between the caller and
// whatever it landed on - which catches nothing if the target is a namespace.
//
// So a path only takes that route if it has the shape of a namespace link and
// the directory holding it really is procfs. Everything else goes through the
// confined open, which refuses it at resolution rather than after opening it.
func TestOpenNetnsPathProcfsCarveOutIsNarrow(t *testing.T) {
	t.Run("a namespace link still opens", func(t *testing.T) {
		saved := host.HostRoot
		host.HostRoot = "/"
		t.Cleanup(func() { host.HostRoot = saved })

		// The shape the gadget tests use. Nothing here needs privileges: it is
		// the caller's own network namespace.
		path := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())

		handle, inode, err := OpenNetnsPath(path)
		require.NoError(t, err, "narrowing the carve-out must not amputate the paths it exists for")
		t.Cleanup(func() { handle.Close() })
		require.NotEqual(t, uint64(0), inode)
		require.Equal(t, statInode(t, path), inode, "the inode must be the one the path refers to")
	})

	t.Run("a symlink below /proc is refused, not opened", func(t *testing.T) {
		hostRoot := t.TempDir()
		outsideDir := t.TempDir()

		saved := host.HostRoot
		host.HostRoot = hostRoot
		t.Cleanup(func() { host.HostRoot = saved })

		outsideFile := filepath.Join(outsideDir, "loot")
		require.NoError(t, os.WriteFile(outsideFile, []byte("out of root"), 0o644))

		require.NoError(t, os.MkdirAll(filepath.Join(hostRoot, "proc", "fake"), 0o755))
		require.NoError(t, os.Symlink(outsideFile, filepath.Join(hostRoot, "proc", "fake", "escape")))

		handle, _, err := OpenNetnsPath("/proc/fake/escape")
		require.Error(t, err)
		require.Equal(t, -1, int(handle), "no file descriptor must be returned on error")
		// The distinction is the whole point: being told it is not a namespace
		// would mean it had been opened, outside the host root, and rejected
		// only because of what it happened to be.
		require.NotContains(t, err.Error(), "does not refer to a namespace",
			"a path below /proc that is not a namespace link must be confined, not opened and then judged")
	})

	t.Run("a namespace link shape off procfs is refused", func(t *testing.T) {
		hostRoot := t.TempDir()
		outsideDir := t.TempDir()

		saved := host.HostRoot
		host.HostRoot = hostRoot
		t.Cleanup(func() { host.HostRoot = saved })

		outsideFile := filepath.Join(outsideDir, "loot")
		require.NoError(t, os.WriteFile(outsideFile, []byte("out of root"), 0o644))

		// Right shape, wrong filesystem: a directory an attacker can write to,
		// dressed up as a namespace directory.
		nsDir := filepath.Join(hostRoot, "proc", "1234", "ns")
		require.NoError(t, os.MkdirAll(nsDir, 0o755))
		require.NoError(t, os.Symlink(outsideFile, filepath.Join(nsDir, "net")))

		handle, _, err := OpenNetnsPath("/proc/1234/ns/net")
		require.Error(t, err)
		require.Equal(t, -1, int(handle), "no file descriptor must be returned on error")
		require.Contains(t, err.Error(), "is not on procfs",
			"the shape alone must not buy an unconfined open")
	})
}

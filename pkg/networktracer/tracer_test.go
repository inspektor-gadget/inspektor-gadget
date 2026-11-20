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

package networktracer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// createTestNetns creates a fresh network namespace and returns a procfs path
// referring to it. The namespace is kept alive by a dedicated thread until the
// test finishes.
func createTestNetns(t *testing.T) string {
	t.Helper()

	pathCh := make(chan string)
	errCh := make(chan error, 1)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	go func() {
		// The thread is deliberately never unlocked: unshare(CLONE_NEWNET) is
		// not reversible, so the thread must die with this goroutine instead
		// of being reused by the runtime.
		runtime.LockOSThread()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
			return
		}

		pathCh <- fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())

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

// bindMountNetns bind mounts the network namespace at nsPath onto a file in a
// temporary directory, mimicking what "ip netns add" does under /run/netns.
// The returned path can be unlinked while the namespace stays alive.
func bindMountNetns(t *testing.T, nsPath string) string {
	t.Helper()

	mountPath := filepath.Join(t.TempDir(), "netns")
	f, err := os.Create(mountPath)
	require.NoError(t, err, "creating bind mount target")
	require.NoError(t, f.Close())

	require.NoError(t, unix.Mount(nsPath, mountPath, "", unix.MS_BIND, ""),
		"bind mounting %q onto %q", nsPath, mountPath)
	t.Cleanup(func() {
		// Ignore errors: the test may have unmounted it already.
		_ = unix.Unmount(mountPath, unix.MNT_DETACH)
		_ = os.Remove(mountPath)
	})

	return mountPath
}

// unlinkNetns removes a bind mounted namespace path, as happens when a pod is
// deleted while a gadget is still attached to its network namespace.
func unlinkNetns(t *testing.T, path string) {
	t.Helper()

	require.NoError(t, unix.Unmount(path, unix.MNT_DETACH), "unmounting %q", path)
	require.NoError(t, os.Remove(path), "removing %q", path)
	require.NoFileExists(t, path)
}

func newTestTracer(t *testing.T) *Tracer[struct{}] {
	t.Helper()

	tracer, err := NewTracer[struct{}]()
	require.NoError(t, err, "creating tracer")
	t.Cleanup(tracer.Close)
	return tracer
}

func TestAttachNetnsPath(t *testing.T) {
	utilstest.RequireRoot(t)

	nsPath := createTestNetns(t)
	var stat unix.Stat_t
	require.NoError(t, unix.Stat(nsPath, &stat))
	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(nsPath))
	a := tracer.netnsAttachment
	require.NotNil(t, a)

	var inode uint32
	require.NoError(t, a.dispatcherObjs.CurrentNetns.Get(&inode))
	require.Equal(t, uint32(stat.Ino), inode, "dispatcher must label events with the selected namespace")
	require.GreaterOrEqual(t, a.sockFd, 0)
	domain, err := unix.GetsockoptInt(a.sockFd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	require.NoError(t, err)
	require.Equal(t, unix.AF_PACKET, domain)
	require.Empty(t, tracer.attachments, "path attachment is independent of container discovery")

	require.ErrorContains(t, tracer.AttachNetnsPath(nsPath), "already attached")
	require.Same(t, a, tracer.netnsAttachment, "a second attach must not replace the original socket")
}

// Close must release the socket and program without resolving the path again:
// the mount may have disappeared while the namespace remained alive.
func TestCloseAfterUnlink(t *testing.T) {
	utilstest.RequireRoot(t)

	// Keep test mounts private even if an assertion fails.
	const marker = "IG_NETWORKTRACER_PRIVATE_MOUNT_TEST"
	if os.Getenv(marker) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestCloseAfterUnlink$", "-test.v")
		cmd.Env = append(os.Environ(), marker+"=1")
		cmd.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: unix.SIGKILL}
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "isolated test subprocess: %s", output)
		return
	}
	require.NoError(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))

	nsPath := createTestNetns(t)
	mountPath := bindMountNetns(t, nsPath)
	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(mountPath))
	fd := tracer.netnsAttachment.sockFd
	prog := tracer.netnsAttachment.dispatcherObjs.IgNetDisp
	unlinkNetns(t, mountPath)

	tracer.Close()
	require.Nil(t, tracer.netnsAttachment)
	_, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	require.ErrorIs(t, err, unix.EBADF, "Close must release the namespace's socket")
	require.Equal(t, -1, prog.FD(), "Close must release the dispatcher program")
}

func TestAttachNetnsPathErrors(t *testing.T) {
	utilstest.RequireRoot(t)

	for _, test := range []struct {
		name        string
		path        string
		errContains string
	}{
		{"nonexistent path", "/run/netns/does-not-exist-4f2c1b", "no such file or directory"},
		{"not a namespace", "/etc/hostname", "does not refer to a namespace"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tracer := newTestTracer(t)
			err := tracer.AttachNetnsPath(test.path)
			require.ErrorContains(t, err, test.path)
			require.ErrorContains(t, err, test.errContains)
			require.Empty(t, tracer.attachments)
			require.Nil(t, tracer.netnsAttachment, "failed attach must not retain resources")
		})
	}
}

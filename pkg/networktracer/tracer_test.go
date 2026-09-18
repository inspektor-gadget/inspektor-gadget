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

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()

	var stat unix.Stat_t
	require.NoError(t, unix.Stat(path, &stat), "stat %q", path)
	return stat.Ino
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
	expectedInode := inodeOf(t, nsPath)

	tracer := newTestTracer(t)

	require.NoError(t, tracer.AttachNetnsPath(nsPath))

	// The attachment must be keyed by the network namespace inode, which is
	// the same keyspace container attachments use.
	require.Len(t, tracer.attachments, 1)
	a, ok := tracer.attachments[expectedInode]
	require.True(t, ok, "attachment must be keyed by the netns inode %d, got keys %v",
		expectedInode, attachmentKeys(tracer))
	require.NotEqual(t, -1, a.sockFd, "attachment must hold an open socket")
	require.Contains(t, a.users, netnsPathUser)

	require.Equal(t, expectedInode, tracer.netnsPaths[nsPath], "path must map to the resolved inode")
}

func TestAttachNetnsPathIsIdempotent(t *testing.T) {
	utilstest.RequireRoot(t)

	nsPath := createTestNetns(t)
	tracer := newTestTracer(t)

	require.NoError(t, tracer.AttachNetnsPath(nsPath))
	require.Len(t, tracer.attachments, 1)
	first := tracer.attachments[inodeOf(t, nsPath)]

	// Attaching again must not create a second attachment nor a second socket.
	require.NoError(t, tracer.AttachNetnsPath(nsPath))
	require.Len(t, tracer.attachments, 1)
	second := tracer.attachments[inodeOf(t, nsPath)]
	require.Same(t, first, second, "the same attachment must be reused")
	require.Equal(t, first.sockFd, second.sockFd, "no additional socket must be opened")

	// A single detach releases it: the second attach was a no-op, not a
	// reference count on the sentinel user.
	require.NoError(t, tracer.DetachNetnsPath(nsPath))
	require.Empty(t, tracer.attachments)
}

func TestDetachNetnsPath(t *testing.T) {
	utilstest.RequireRoot(t)

	nsPath := createTestNetns(t)
	tracer := newTestTracer(t)

	require.NoError(t, tracer.AttachNetnsPath(nsPath))
	require.NoError(t, tracer.DetachNetnsPath(nsPath))

	require.Empty(t, tracer.attachments, "detach must release the attachment")
	require.Empty(t, tracer.netnsPaths, "detach must forget the path")

	// Detaching twice is an error, not a crash.
	require.Error(t, tracer.DetachNetnsPath(nsPath))
}

func TestDetachNetnsPathNotAttached(t *testing.T) {
	utilstest.RequireRoot(t)

	tracer := newTestTracer(t)

	err := tracer.DetachNetnsPath("/run/netns/never-attached")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not attached")
}

// TestDetachNetnsPathAfterUnlink covers the pod-deleted case: the path is gone
// but the namespace is still alive through the attachment's socket, so detach
// must succeed by using the inode resolved at attach time.
func TestDetachNetnsPathAfterUnlink(t *testing.T) {
	utilstest.RequireRoot(t)

	nsPath := createTestNetns(t)
	mountPath := bindMountNetns(t, nsPath)
	expectedInode := inodeOf(t, mountPath)

	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(mountPath))
	require.Contains(t, tracer.attachments, expectedInode)

	unlinkNetns(t, mountPath)

	require.NoError(t, tracer.DetachNetnsPath(mountPath),
		"detach must not depend on the path still existing")
	require.Empty(t, tracer.attachments)
	require.Empty(t, tracer.netnsPaths)
}

// TestCloseAfterUnlink is the gadget-stop equivalent of the above: Close()
// must release everything even though the path is gone.
func TestCloseAfterUnlink(t *testing.T) {
	utilstest.RequireRoot(t)

	nsPath := createTestNetns(t)
	mountPath := bindMountNetns(t, nsPath)

	tracer, err := NewTracer[struct{}]()
	require.NoError(t, err)

	require.NoError(t, tracer.AttachNetnsPath(mountPath))
	require.Len(t, tracer.attachments, 1)

	unlinkNetns(t, mountPath)

	tracer.Close()
	require.Empty(t, tracer.attachments, "Close() must release the attachment")
	require.Empty(t, tracer.netnsPaths, "Close() must forget the paths")
}

func TestAttachNetnsPathErrors(t *testing.T) {
	utilstest.RequireRoot(t)

	tests := []struct {
		name        string
		path        string
		errContains string
	}{
		{
			name:        "nonexistent path",
			path:        "/run/netns/does-not-exist-4f2c1b",
			errContains: "no such file or directory",
		},
		{
			name:        "not a namespace",
			path:        "/etc/hostname",
			errContains: "does not refer to a namespace",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tracer := newTestTracer(t)

			err := tracer.AttachNetnsPath(test.path)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.path, "error must mention the offending path")
			require.Contains(t, err.Error(), test.errContains)

			require.Empty(t, tracer.attachments, "no attachment must be created on failure")
			require.Empty(t, tracer.netnsPaths, "no path must be recorded on failure")
		})
	}
}

// TestAttachNetnsPathDedupsWithSameNetns checks that two paths referring to the
// same namespace share a single attachment and that it survives until the last
// path is detached.
func TestAttachNetnsPathDedupsWithSameNetns(t *testing.T) {
	utilstest.RequireRoot(t)

	nsPath := createTestNetns(t)
	mountPath := bindMountNetns(t, nsPath)
	require.Equal(t, inodeOf(t, nsPath), inodeOf(t, mountPath), "both paths must refer to the same netns")

	tracer := newTestTracer(t)

	require.NoError(t, tracer.AttachNetnsPath(nsPath))
	require.NoError(t, tracer.AttachNetnsPath(mountPath))
	require.Len(t, tracer.attachments, 1, "both paths share one attachment")

	require.NoError(t, tracer.DetachNetnsPath(nsPath))
	require.Len(t, tracer.attachments, 1, "attachment must survive while a path still references it")

	require.NoError(t, tracer.DetachNetnsPath(mountPath))
	require.Empty(t, tracer.attachments)
}

func rebindNetns(t *testing.T, mountPath, nsPath string) {
	t.Helper()
	require.NoError(t, unix.Unmount(mountPath, unix.MNT_DETACH), "unmounting old namespace")
	require.NoError(t, unix.Mount(nsPath, mountPath, "", unix.MS_BIND, ""),
		"binding replacement namespace")
}

func TestAttachNetnsPathRebindReleasesOldNamespace(t *testing.T) {
	utilstest.RequireRoot(t)

	firstPath := createTestNetns(t)
	secondPath := createTestNetns(t)
	mountPath := bindMountNetns(t, firstPath)
	firstInode := inodeOf(t, firstPath)
	secondInode := inodeOf(t, secondPath)
	require.NotEqual(t, firstInode, secondInode)

	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(mountPath))

	rebindNetns(t, mountPath, secondPath)
	require.NoError(t, tracer.AttachNetnsPath(mountPath))

	require.NotContains(t, tracer.attachments, firstInode,
		"moving the only path user must release the old attachment")
	require.Contains(t, tracer.attachments, secondInode)
	require.Equal(t, secondInode, tracer.netnsPaths[mountPath])

	require.NoError(t, tracer.DetachNetnsPath(mountPath))
	require.Empty(t, tracer.attachments)
}

func TestAttachNetnsPathRebindPreservesAlias(t *testing.T) {
	utilstest.RequireRoot(t)

	firstPath := createTestNetns(t)
	secondPath := createTestNetns(t)
	movingPath := bindMountNetns(t, firstPath)
	aliasPath := bindMountNetns(t, firstPath)
	firstInode := inodeOf(t, firstPath)
	secondInode := inodeOf(t, secondPath)

	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(movingPath))
	require.NoError(t, tracer.AttachNetnsPath(aliasPath))

	rebindNetns(t, movingPath, secondPath)
	require.NoError(t, tracer.AttachNetnsPath(movingPath))

	require.Contains(t, tracer.attachments, firstInode,
		"the old attachment must survive while an alias still refers to it")
	require.Contains(t, tracer.attachments, secondInode)
	require.Equal(t, firstInode, tracer.netnsPaths[aliasPath])
	require.Equal(t, secondInode, tracer.netnsPaths[movingPath])

	require.NoError(t, tracer.DetachNetnsPath(aliasPath))
	require.NotContains(t, tracer.attachments, firstInode)
	require.Contains(t, tracer.attachments, secondInode)
	require.NoError(t, tracer.DetachNetnsPath(movingPath))
	require.Empty(t, tracer.attachments)
}

func TestAttachNetnsPathRebindPreservesContainerUser(t *testing.T) {
	utilstest.RequireRoot(t)

	firstPath := createTestNetns(t)
	secondPath := createTestNetns(t)
	movingPath := bindMountNetns(t, firstPath)
	firstInode := inodeOf(t, firstPath)
	secondInode := inodeOf(t, secondPath)

	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(movingPath))

	// Model an attachment shared with container discovery. Attach() adds the
	// container pid to this same users set after deduplicating by inode.
	const containerPID = uint32(4242)
	tracer.attachments[firstInode].users[containerPID] = struct{}{}

	rebindNetns(t, movingPath, secondPath)
	require.NoError(t, tracer.AttachNetnsPath(movingPath))

	old := tracer.attachments[firstInode]
	require.NotNil(t, old, "a container user must keep the old attachment alive")
	require.Contains(t, old.users, containerPID)
	require.NotContains(t, old.users, netnsPathUser)
	require.Contains(t, tracer.attachments, secondInode)

	require.NoError(t, tracer.Detach(containerPID))
	require.NotContains(t, tracer.attachments, firstInode)
	require.NoError(t, tracer.DetachNetnsPath(movingPath))
	require.Empty(t, tracer.attachments)
}

func TestAttachNetnsPathRebindRollsBackOnCreateFailure(t *testing.T) {
	utilstest.RequireRoot(t)

	firstPath := createTestNetns(t)
	secondPath := createTestNetns(t)
	mountPath := bindMountNetns(t, firstPath)
	firstInode := inodeOf(t, firstPath)
	secondInode := inodeOf(t, secondPath)

	tracer := newTestTracer(t)
	require.NoError(t, tracer.AttachNetnsPath(mountPath))
	oldAttachment := tracer.attachments[firstInode]

	tracer.mu.Lock()
	err := tracer.attachNetnsPath(mountPath, secondInode, func() (int, error) {
		return -1, fmt.Errorf("injected socket failure")
	})
	tracer.mu.Unlock()

	require.ErrorContains(t, err, "injected socket failure")
	require.Equal(t, firstInode, tracer.netnsPaths[mountPath],
		"a failed replacement must preserve the old path association")
	require.Same(t, oldAttachment, tracer.attachments[firstInode],
		"a failed replacement must preserve the old attachment")
	require.NotContains(t, tracer.attachments, secondInode)

	require.NoError(t, tracer.DetachNetnsPath(mountPath))
	require.Empty(t, tracer.attachments)
}

func attachmentKeys(t *Tracer[struct{}]) []uint64 {
	keys := make([]uint64, 0, len(t.attachments))
	for k := range t.attachments {
		keys = append(keys, k)
	}
	return keys
}

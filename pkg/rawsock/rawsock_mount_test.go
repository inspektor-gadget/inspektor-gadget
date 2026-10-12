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
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// privateMountTest re-execs just this test in a fresh mount namespace before
// any test mounts occur. Mount propagation is disabled in the child, so even
// failed assertions cannot change the caller's mounts. Extra clone flags let
// the hostPID=false test also start in an actual private PID namespace.
func privateMountTest(t *testing.T, extraFlags uintptr) bool {
	t.Helper()
	utilstest.RequireRoot(t)
	const marker = "IG_RAWSOCK_PRIVATE_MOUNT_TEST"
	if os.Getenv(marker) == t.Name() {
		require.NoError(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""), "make child mount propagation private")
		return true
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	cmd.Env = append(os.Environ(), marker+"="+t.Name())
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNS | extraFlags,
		Pdeathsig:  unix.SIGKILL,
	}
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "isolated test subprocess: %s", output)
	t.Logf("isolated test subprocess:\n%s", output)
	return false
}

func TestOpenNetnsPathMountedProcfs(t *testing.T) {
	if !privateMountTest(t, 0) {
		return
	}
	root := t.TempDir()
	saved := host.HostRoot
	host.HostRoot = root
	t.Cleanup(func() { host.HostRoot = saved })

	for _, prefix := range []string{"proc", "alternate-proc"} {
		mount := filepath.Join(root, prefix)
		require.NoError(t, os.Mkdir(mount, 0o755))
		require.NoError(t, unix.Mount("proc", mount, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""))
		t.Cleanup(func() { require.NoError(t, unix.Unmount(mount, unix.MNT_DETACH)) })
		for _, leading := range []string{"/", ""} {
			path := fmt.Sprintf("%s%s/%d/ns/net", leading, prefix, os.Getpid())
			handle, inode, err := OpenNetnsPath(path)
			require.NoError(t, err, "root-relative procfs at %q", path)
			require.Equal(t, statInode(t, "/proc/self/ns/net"), inode)
			require.NoError(t, handle.Close())
		}

		handle, _, err := OpenNetnsPath(filepath.Join(mount, "self", "ns", "net"))
		require.Error(t, err, "the host-root mount prefix is not an input alias")
		require.Equal(t, -1, int(handle))
		require.NotContains(t, err.Error(), "does not refer to a namespace")
	}
}

func TestOpenNetnsPathHostProcfsWithoutHostPID(t *testing.T) {
	if !privateMountTest(t, unix.CLONE_NEWPID) {
		return
	}
	require.Equal(t, 1, os.Getpid(), "the child must actually run in a private PID namespace")

	// Before overmounting /proc, it is still the inherited host procfs. Capture
	// the child's host PID and preserve that procfs below the simulated /host.
	hostPID, err := os.Readlink("/proc/self")
	require.NoError(t, err)
	require.NotEqual(t, "1", hostPID)
	want := statInode(t, "/proc/self/ns/net")
	root := t.TempDir()
	hostProc := filepath.Join(root, "proc")
	require.NoError(t, os.Mkdir(hostProc, 0o755))
	require.NoError(t, unix.Mount("/proc", hostProc, "", unix.MS_BIND, ""))
	t.Cleanup(func() { require.NoError(t, unix.Unmount(hostProc, unix.MNT_DETACH)) })

	// A container's /proc now exposes only the private PID namespace. No host
	// filesystem or sysctl is changed: both mounts exist only in this child.
	require.NoError(t, unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""))
	t.Cleanup(func() { require.NoError(t, unix.Unmount("/proc", unix.MNT_DETACH)) })
	var stat unix.Stat_t
	require.ErrorIs(t, unix.Stat("/proc/"+hostPID+"/ns/net", &stat), unix.ENOENT,
		"the host PID must not be visible in the container procfs")

	saved := host.HostRoot
	host.HostRoot = root
	t.Cleanup(func() { host.HostRoot = saved })
	handle, inode, err := OpenNetnsPath("/proc/" + hostPID + "/ns/net")
	require.NoError(t, err, "host procfs exposure, not hostPID, must govern lookup")
	t.Cleanup(func() { handle.Close() })
	require.Equal(t, want, inode)

	rejectedHandle, _, err := OpenNetnsPath(filepath.Join(root, "proc", hostPID, "ns", "net"))
	require.Error(t, err, "host-root-prefixed input must not be accepted as an alias")
	require.Equal(t, -1, int(rejectedHandle))
}

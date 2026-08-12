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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// raceIterations is how many times the racing test below calls OpenNetnsPath().
// The window an implementation that resolves to a string and opens it
// afterwards leaves open is a few microseconds wide, so a handful of attempts
// proves nothing. At this count the previous implementation loses the race
// within the first few hundred iterations every time it is run.
const raceIterations = 20000

// TestOpenNetnsPathRacesPathSwap is a regression test for the time-of-check to
// time-of-use flaw fixed by resolving and opening in one operation.
//
// It cannot be written as a static test. securejoin.SecureJoin() clamps a
// symlink that is already in place exactly as the atomic resolution does, so
// against any path that just sits there the two implementations agree. They
// only diverge while the filesystem changes underneath: SecureJoin() returns a
// path string, and every directory component of that string is traversed again
// by the open that follows, so replacing one of them in between redirects the
// open out of the host root.
//
// The setup is therefore a path whose two possible states are both safe, so
// that reaching the out-of-root file proves the open used a resolution that had
// already gone stale:
//
//	<root>/run/netns    a directory that does not contain "target"
//	<root>/run/swap     a symlink to a directory outside the root that does
//
// A goroutine exchanges the two names atomically, over and over. Asking for
// /run/netns/target must always fail: when "netns" is the directory there is
// nothing called "target" in it, and when it is the symlink the target
// directory is outside the root and gets clamped to a path that does not exist.
// An implementation with a window can still resolve the first state and open
// the second.
//
// The assertion is on confinement, not on the namespace check that follows it.
// The out-of-root file is deliberately an ordinary file, which nsfs validation
// would reject anyway; being told that it "does not refer to a namespace" is
// itself the proof that it was opened, and opening a file outside the host root
// is the whole of the vulnerability. Waiting for a target that passes
// validation would miss every case where the escape lands on something else.
func TestOpenNetnsPathRacesPathSwap(t *testing.T) {
	hostRoot := t.TempDir()
	// A sibling of hostRoot, so nothing below hostRoot can legitimately reach
	// it.
	outsideDir := t.TempDir()
	require.NotContains(t, outsideDir, hostRoot, "the outside directory must not be below the host root")

	saved := host.HostRoot
	host.HostRoot = hostRoot
	t.Cleanup(func() { host.HostRoot = saved })

	outsideFile := filepath.Join(outsideDir, "target")
	require.NoError(t, os.WriteFile(outsideFile, []byte("out of root"), 0o644))

	// The directory state: present, and without a "target" in it.
	netnsDir := filepath.Join(hostRoot, "run", "netns")
	require.NoError(t, os.MkdirAll(netnsDir, 0o755))

	// The symlink state, parked under a second name until the racer swaps it in.
	swapLink := filepath.Join(hostRoot, "run", "swap")
	require.NoError(t, os.Symlink(outsideDir, swapLink))

	// Both states are individually safe. Check that before racing them, so a
	// failure below can only come from the window between resolving and opening
	// and never from a setup that was reachable to begin with.
	for _, state := range []string{"directory", "symlink"} {
		handle, _, err := OpenNetnsPath("/run/netns/target")
		require.Error(t, err, "the %s state must not resolve to anything", state)
		require.Equal(t, -1, int(handle))
		require.NotContains(t, err.Error(), "does not refer to a namespace",
			"the %s state must fail before opening anything, or the race below proves nothing", state)
		require.NoError(t, exchange(netnsDir, swapLink))
	}
	// The loop above swapped twice, so the names are back where they started.

	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			// Ignore errors: the exchange races nothing but itself here, and a
			// failure only costs this iteration.
			_ = exchange(netnsDir, swapLink)
		}
	}()
	t.Cleanup(func() {
		stop.Store(true)
		<-done
	})

	for i := range raceIterations {
		handle, _, err := OpenNetnsPath("/run/netns/target")
		if err == nil {
			handle.Close()
			t.Fatalf("iteration %d: /run/netns/target resolved to something, "+
				"but neither state of the path is reachable from inside the host root", i)
		}
		require.Equal(t, -1, int(handle), "iteration %d: no descriptor may be returned on error", i)
		require.NotContains(t, err.Error(), "does not refer to a namespace",
			"iteration %d: %q was opened, so the path was resolved and opened as two operations", i, outsideFile)
	}
}

// exchange atomically swaps the names of two existing paths. Unlike rename it
// leaves no instant in which either name is missing, so a failure in the test
// above is a lost race and never a file that briefly was not there.
func exchange(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}

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

package containerhook

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPermissionResponseBoundValidation(t *testing.T) {
	prevBound := configuredPermResponseBound.Load()
	prevPidFile := configuredPidFileResponseBound.Load()
	t.Cleanup(func() {
		configuredPermResponseBound.Store(prevBound)
		configuredPidFileResponseBound.Store(prevPidFile)
	})
	configuredPermResponseBound.Store(0)
	configuredPidFileResponseBound.Store(0)
	require.Equal(t, defaultPermResponseBound, PermissionResponseBound())
	require.Equal(t, defaultPidFileResponseBound, PidFileResponseBound())

	for _, invalid := range []time.Duration{0, minPermResponseBound - 1, maxPermResponseBound + 1} {
		require.Error(t, SetPermissionResponseBound(invalid))
		require.Error(t, SetPidFileResponseBound(invalid))
	}

	require.NoError(t, SetPermissionResponseBound(2*time.Second))
	require.NoError(t, SetPidFileResponseBound(10*time.Second))
	require.Equal(t, 2*time.Second, PermissionResponseBound())
	require.Equal(t, 10*time.Second, PidFileResponseBound())
}

const gkTestBound = 300 * time.Millisecond

type gkTestEnv struct {
	g             *gatekeeperProc
	path          string
	runtimeNotify *fanotify.NotifyFD
	pidNotify     *fanotify.NotifyFD
}

// gkTestSetup starts a real gatekeeper process (this test binary re-executed,
// or IG_CONTAINER_HOOK_GATEKEEPER_BIN) for a pid-file group with FAN_OPEN_PERM
// on a temp file. The runtime group is an unmarked fanotify group and there is
// no record queue.
func gkTestSetup(t *testing.T) (*gatekeeperProc, string) {
	env := gkTestSetupEnv(t)
	return env.g, env.path
}

func gkTestSetupEnv(t *testing.T) *gkTestEnv {
	t.Helper()
	if os.Getenv(gatekeeperBinEnv) == "" {
		// Test this binary, not whatever gatekeeper the host has installed.
		t.Setenv(gatekeeperBinEnv, "/proc/self/exe")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for fanotify permission events")
	}
	runtimeNotify, err := initFanotify()
	require.NoError(t, err)
	t.Cleanup(func() { runtimeNotify.File.Close() })
	pidNotify, err := initFanotify()
	require.NoError(t, err)
	t.Cleanup(func() { pidNotify.File.Close() })

	path := filepath.Join(t.TempDir(), "watched")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	g, err := startGatekeeper(runtimeNotify.Fd, pidNotify.Fd, -1, 0, gkTestBound, gkTestBound)
	require.NoError(t, err)
	t.Cleanup(g.close)

	// startGatekeeper returned after the ready message: the gatekeeper
	// reads the groups, so marks can be added, as install() does.
	require.NoError(t, pidNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, path))
	return &gkTestEnv{g: g, path: path, runtimeNotify: runtimeNotify, pidNotify: pidNotify}
}

// timedOpen opens path and returns how long open() blocked.
func timedOpen(t *testing.T, path string) time.Duration {
	start := time.Now()
	f, err := os.Open(path)
	took := time.Since(start)
	require.NoError(t, err)
	f.Close()
	return took
}

func TestGatekeeperForwardsToAResponsiveParent(t *testing.T) {
	g, path := gkTestSetup(t)
	g.startReceive(nil)

	var mu sync.Mutex
	var paths []string
	go func() {
		for ev := range g.pidCh {
			// The parent gets a working copy of the event fd.
			p, err := ev.data.GetPath()
			if err == nil {
				mu.Lock()
				paths = append(paths, p)
				mu.Unlock()
			}
			ev.data.Close()
			g.done(ev.seq)
		}
	}()

	for i := 0; i < 100; i++ {
		require.Less(t, timedOpen(t, path), gkTestBound/2, "open %d waited for the deadline instead of the parent", i)
	}
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, paths, 100)
	require.Equal(t, path, paths[0])
}

func TestGatekeeperAllowsWhenParentNeverReplies(t *testing.T) {
	g, path := gkTestSetup(t)
	// The parent receives events but is stuck and never answers.
	g.startReceive(nil)
	var mu sync.Mutex
	var held []*fanotify.EventMetadata
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, d := range held {
			d.Close()
		}
	})
	go func() {
		for ev := range g.pidCh {
			mu.Lock()
			held = append(held, ev.data)
			mu.Unlock()
		}
	}()

	var wg sync.WaitGroup
	took := make([]time.Duration, 8)
	for i := range took {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			took[i] = timedOpen(t, path)
		}(i)
	}
	wg.Wait()
	for i, d := range took {
		require.GreaterOrEqual(t, d, gkTestBound*2/3, "open %d returned before the deadline", i)
		require.Less(t, d, gkTestBound+500*time.Millisecond, "open %d not released at the deadline", i)
	}
}

func TestGatekeeperAllowsWhenParentDoesNotEvenReceive(t *testing.T) {
	_, path := gkTestSetup(t)
	// No receive loop at all: events pile up in the socket, then it fills.
	var wg sync.WaitGroup
	took := make([]time.Duration, 64)
	for i := range took {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			took[i] = timedOpen(t, path)
		}(i)
	}
	wg.Wait()
	for i, d := range took {
		require.Less(t, d, gkTestBound+500*time.Millisecond, "open %d not released at the deadline", i)
	}
}

func TestGatekeeperCloseAllowsPendingAndExits(t *testing.T) {
	g, path := gkTestSetup(t)
	g.startReceive(nil)
	go func() {
		for ev := range g.pidCh {
			ev.data.Close() // never replies
		}
	}()

	opened := make(chan time.Duration)
	go func() { opened <- timedOpen(t, path) }()
	time.Sleep(50 * time.Millisecond)
	g.close()
	select {
	case <-opened:
	case <-time.After(gkTestBound):
		t.Fatal("pending event not allowed on close")
	}
	select {
	case <-g.exited:
	default:
		t.Fatal("gatekeeper still running after close")
	}
}

// The gatekeeper dies while we hold events and do not drain the socket: its
// exit, not a socket EOF behind the backlog, must trigger closing the groups,
// so pending and new opens go through promptly.
func TestGatekeeperLossClosesTheGroupsPromptly(t *testing.T) {
	env := gkTestSetupEnv(t)
	g := env.g
	stop := make(chan bool)
	t.Cleanup(func() { close(stop) })

	lost := make(chan struct{})
	var once sync.Once
	go g.watchExit(stop, func(error) {
		// What ContainerNotifier.onGatekeeperLost does.
		once.Do(func() {
			env.runtimeNotify.File.Close()
			env.pidNotify.File.Close()
			close(lost)
		})
	})
	// No receive loop: everything forwarded stays queued in the socket.

	opened := make(chan time.Duration, 4)
	for i := 0; i < 4; i++ {
		go func() { opened <- timedOpen(t, env.path) }()
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	require.NoError(t, g.cmd.Process.Kill())

	select {
	case <-lost:
	case <-time.After(time.Second):
		t.Fatal("gatekeeper exit not noticed")
	}
	for i := 0; i < 4; i++ {
		select {
		case <-opened:
		case <-time.After(time.Second):
			t.Fatal("open still blocked after the gatekeeper died")
		}
	}
	// Well before the deadline the gatekeeper would have applied.
	require.Less(t, time.Since(start), gkTestBound+500*time.Millisecond)
	require.Less(t, timedOpen(t, env.path), 100*time.Millisecond, "the group must be gone")
}

// A gatekeeper that speaks another protocol is refused before any mark.
func TestGatekeeperRefusesAnotherProtocolVersion(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for fanotify")
	}
	notify, err := initFanotify()
	require.NoError(t, err)
	t.Cleanup(func() { notify.File.Close() })
	t.Setenv(gatekeeperBinEnv, "/bin/true")
	_, err = startGatekeeper(notify.Fd, notify.Fd, -1, 0, gkTestBound, gkTestBound)
	require.Error(t, err)
}

func TestGatekeeperRefusesARecordSizeMismatch(t *testing.T) {
	_, err := startGatekeeper(-1, -1, 0, recordSize+8, gkTestBound, gkTestBound)
	require.ErrorContains(t, err, "value size")
}

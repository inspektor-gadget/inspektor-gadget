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

package command

import (
	"bytes"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStderrLineProcessor(t *testing.T) {
	var store bytes.Buffer
	var observed []string

	p := &stderrLineProcessor{
		observer: func(line string) { observed = append(observed, line) },
		store:    &store,
	}

	// Write in chunks that split lines across Write calls to exercise the line buffering.
	writes := []string{"keep-1\ndr", "op-me\nke", "ep-2\n", "partial-no-newline"}
	for _, w := range writes {
		n, err := p.Write([]byte(w))
		require.NoError(t, err)
		require.Equal(t, len(w), n)
	}

	// The observer sees every complete line.
	assert.Equal(t, []string{"keep-1", "drop-me", "keep-2"}, observed)

	// The store keeps every line; the trailing line without a newline is not flushed.
	assert.Equal(t, "keep-1\ndrop-me\nkeep-2\n", store.String())

	// After the process exits, flush emits the final unterminated line so it is not lost.
	p.flush()
	assert.Equal(t, []string{"keep-1", "drop-me", "keep-2", "partial-no-newline"}, observed)
	assert.Equal(t, "keep-1\ndrop-me\nkeep-2\npartial-no-newline", store.String())

	// A second flush is a no-op.
	p.flush()
	assert.Equal(t, "keep-1\ndrop-me\nkeep-2\npartial-no-newline", store.String())
}

func TestKillErrorAllowingSignal(t *testing.T) {
	const sig = syscall.SIGKILL

	// nil error stays nil.
	assert.NoError(t, killErrorAllowingSignal(nil, sig))

	// A non-ExitError is returned as-is.
	sentinel := errors.New("boom")
	assert.ErrorIs(t, killErrorAllowingSignal(sentinel, sig), sentinel)

	// Being terminated by the signal we sent is expected => nil.
	killed := exec.Command("/bin/sh", "-c", "kill -KILL $$").Run()
	require.Error(t, killed)
	assert.NoError(t, killErrorAllowingSignal(killed, sig))

	// A non-zero exit that is not our signal is a real error and is returned.
	exited := exec.Command("/bin/sh", "-c", "exit 3").Run()
	require.Error(t, exited)
	assert.Error(t, killErrorAllowingSignal(exited, sig))
}

func TestTrackExit_EarlyExitObservable(t *testing.T) {
	// A tracked command that exits on its own has its exit observable via ExitCh()/ExitErr()
	// without a second Wait().
	c := &Command{Name: "early-exit", Cmd: exec.Command("/bin/sh", "-c", "exit 3")}
	c.TrackExit()
	c.Start(t)

	select {
	case <-c.ExitCh():
	case <-time.After(10 * time.Second):
		t.Fatal("tracked command exit was not observed")
	}
	assert.Error(t, c.ExitErr(), "expected a non-zero exit error")

	// kill() on an already-exited tracked command does not double-Wait and surfaces the
	// non-zero exit (a clean/SIGKILL exit would return nil).
	assert.Error(t, c.kill(), "kill must report a non-zero self-exit")
}

func TestTrackExit_KillStillRunning(t *testing.T) {
	// A tracked command that is still running is stopped via kill(), which reaps through the
	// background goroutine and treats the SIGKILL as expected (no error).
	c := &Command{Name: "long-running", Cmd: exec.Command("/bin/sh", "-c", "sleep 30")}
	c.TrackExit()
	c.Start(t)

	// It should not have exited yet.
	select {
	case <-c.ExitCh():
		t.Fatal("command exited unexpectedly")
	case <-time.After(200 * time.Millisecond):
	}

	assert.NoError(t, c.kill())
}

func TestTrackExit_CleanSelfExitNotAnError(t *testing.T) {
	// A tracked command that exits 0 on its own is not reported as a kill error.
	c := &Command{Name: "clean-exit", Cmd: exec.Command("/bin/sh", "-c", "exit 0")}
	c.TrackExit()
	c.Start(t)

	select {
	case <-c.ExitCh():
	case <-time.After(10 * time.Second):
		t.Fatal("tracked command exit was not observed")
	}
	assert.NoError(t, c.ExitErr())
	assert.NoError(t, c.kill())
}

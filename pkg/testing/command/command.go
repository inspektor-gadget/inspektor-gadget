// Copyright 2019-2024 The Inspektor Gadget authors
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

// Package command provides a generic way for running testing commands.
package command

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

type Command struct {
	// Name of the command to be run, used to give information.
	Name string

	// ValidateOutput is a function used to verify the output. It must make the test fail in
	// case of error.
	ValidateOutput func(t *testing.T, output string)

	// ValidateStdErrOutput is a function used to verify the output. It must make the test fail in
	// case of error.
	ValidateStdErrOutput func(t *testing.T, output string)

	// StdOutWriter is an optional writer to which the command's standard output will be written.
	// It's used in situations where we want to process the output on-line without saving it.
	StdOutWriter io.Writer

	// StartAndStop indicates this command should first be started then stopped.
	// It corresponds to gadget like execsnoop which wait user to type Ctrl^C.
	StartAndStop bool

	// started indicates this command was started.
	// It is only used by command which have StartAndStop set.
	started bool

	// Cmd object is used when we want to start the command, then do
	// other stuff and wait for its completion or just run the command.
	Cmd *exec.Cmd

	// stdout contains command standard output when started using Startcommand().
	stdout bytes.Buffer

	// stderr contains command standard output when started using Startcommand().
	stderr bytes.Buffer
}

func (c *Command) IsStartAndStop() bool {
	return c.StartAndStop
}

func (c *Command) Running() bool {
	return c.started
}

// initExecCmd configures c.Cmd to store the stdout and stderr in c.stdout and c.stderr so that we
// can use them on c.verifyOutput().
func (c *Command) initExecCmd() {
	c.Cmd.Stdout = &c.stdout
	c.Cmd.Stderr = &c.stderr

	if c.StdOutWriter != nil {
		c.Cmd.Stdout = c.StdOutWriter
	}

	// To be able to kill the process of /bin/sh and its child (the process of
	// c.Cmd), we need to send the termination signal to their process group ID
	// (PGID). However, child processes get the same PGID as their parents by
	// default, so in order to avoid killing also the integration tests process,
	// we set the fields Setpgid and Pgid of syscall.SysProcAttr before
	// executing /bin/sh. Doing so, the PGID of /bin/sh (and its children)
	// will be set to its process ID, see:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.8:src/syscall/exec_linux.go;l=32-34.
	c.Cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
}

// verifyOutput verifies the output of the command by using the
// ValidateOutput callback function provided by the user.
func (c *Command) verifyOutput(t *testing.T) {
	if c.ValidateOutput != nil {
		c.ValidateOutput(t, c.stdout.String())
	}
}

// verifyStderrOutput verifies the output of the command by using the
// ValidateStdErrOutput callback function provided by the user.
func (c *Command) verifyStderrOutput(t *testing.T) {
	if c.ValidateStdErrOutput != nil {
		c.ValidateStdErrOutput(t, c.stderr.String())
	}
}

// Run runs the Command on the given as parameter test.
func (c *Command) Run(t *testing.T) {
	c.initExecCmd()

	t.Logf("Run command(%s):\n", c.Name)
	err := c.Cmd.Run()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())
	require.NoError(t, err, "failed to run command(%s)", c.Name)

	c.verifyStderrOutput(t)
	c.verifyOutput(t)
}

// Start starts the Command on the given as parameter test, you need to
// wait it using Stop().
func (c *Command) Start(t *testing.T) {
	if c.started {
		t.Logf("Warn(%s): trying to start command but it was already started\n", c.Name)
		return
	}

	c.initExecCmd()

	t.Logf("Start command(%s)", c.Name)
	err := c.Cmd.Start()
	require.NoError(t, err, "failed to start command(%s)", c.Name)

	c.started = true
}

// Stop stops a Command previously started with Start().
// To do so, it Kill() the process corresponding to this Cmd and then wait for
// its termination.
// Cmd output is then checked with regard to ExpectedString, ExpectedRegexp or ExpectedEntries.
func (c *Command) Stop(t *testing.T) {
	if !c.started {
		t.Logf("Warn(%s): trying to stop command but it was not started\n", c.Name)
		return
	}

	t.Logf("Stop command(%s)\n", c.Name)
	err := c.kill()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())
	require.NoError(t, err, "failed to kill command(%s)", c.Name)

	c.verifyOutput(t)

	c.started = false
}

// kill kills a command by sending SIGKILL because we want to stop the process
// immediately and avoid that the signal is trapped.
func (c *Command) kill() error {
	const sig syscall.Signal = syscall.SIGKILL

	// No need to kill, command has not been executed yet or it already exited
	if c.Cmd == nil || (c.Cmd.ProcessState != nil && c.Cmd.ProcessState.Exited()) {
		return nil
	}

	// Given that we set Setpgid, here we just need to send the PID of c.Cmd
	// (which is the same PGID) as a negative number to syscall.Kill(). As a
	// result, the signal will be received by all the processes with such PGID,
	// in our case, the process of /bin/sh and c.Cmd.
	err := syscall.Kill(-c.Cmd.Process.Pid, sig)
	if err != nil {
		return err
	}

	// In some cases, we do not have to wait here because the cmd was executed
	// with run(), which already waits. On the contrary, in the case it was
	// executed with start() thus ig.started is true, we need to wait indeed.
	if c.started {
		err = c.Cmd.Wait()
		if err == nil {
			return nil
		}

		// Verify if the error is about the signal we just sent. In that case,
		// do not return error, it is what we were expecting.
		var exiterr *exec.ExitError
		if ok := errors.As(err, &exiterr); !ok {
			return err
		}

		waitStatus, ok := exiterr.Sys().(syscall.WaitStatus)
		if !ok {
			return err
		}

		if waitStatus.Signal() != sig {
			return err
		}

		return nil
	}

	return err
}

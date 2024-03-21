// Copyright 2019-2021 The Inspektor Gadget authors
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

package ig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/blang/semver"
)

type IG struct {
	path    string
	image   string
	version semver.Version

	cmd    *exec.Cmd
	env    []string
	flags  []string
	Stdout bytes.Buffer
	Stderr bytes.Buffer

	// StartAndStop indicates this command should first be started then stopped.
	// It corresponds to gadget like execsnoop which wait user to type Ctrl^C.
	startAndStop bool

	// started indicates this command was started.
	// It is only used by command which have StartAndStop set.
	started bool
}

func (ig *IG) IsStartAndStop() bool {
	return ig.startAndStop
}

func (ig *IG) Running() bool {
	return ig.started
}

func (ig *IG) createCmd() {
	args := append([]string{"run", ig.image}, ig.flags...)
	cmd := exec.Command(ig.path, args...)

	ig.env = append(ig.env, "IG_EXPERIMENTAL=true")
	cmd.Env = append(cmd.Env, ig.env...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = &ig.Stdout
	cmd.Stderr = &ig.Stderr

	// To be able to kill the process of ig.cmd,
	// we need to send the termination signal to their process group ID
	// (PGID). However, child processes get the same PGID as their parents by
	// default, so in order to avoid killing also the integration tests process,
	// we set the fields Setpgid and Pgid of syscall.SysProcAttr before
	// executing ig.cmd. Doing so, the PGID of ig.cmd (and its children)
	// will be set to its process ID, see:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.8:src/syscall/exec_linux.go;l=32-34.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}

	ig.cmd = cmd
}

func (ig *IG) RunCmd() error {
	ig.createCmd()
	if err := ig.cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (ig *IG) StartCmd() error {
	if ig.started {
		return fmt.Errorf("Warn(%v): trying to start command but it was already started", ig.cmd)
	}

	ig.createCmd()
	if err := ig.cmd.Start(); err != nil {
		return err
	}

	ig.started = true

	return nil
}

// kill kills a command by sending SIGKILL because we want to stop the process
// immediatly and avoid that the signal is trapped.
func (ig *IG) kill() error {
	const sig syscall.Signal = syscall.SIGKILL

	// No need to kill, command has not been executed yet or it already exited
	if ig.cmd == nil || (ig.cmd.ProcessState != nil && ig.cmd.ProcessState.Exited()) {
		return nil
	}

	// Given that we set Setpgid, here we just need to send the PID of ig.cmd
	// (which is the same PGID) as a negative number to syscall.Kill(). As a
	// result, the signal will be received by all the processes with such PGID,
	// in our case, the process of ig.cmd.
	err := syscall.Kill(-ig.cmd.Process.Pid, sig)
	if err != nil {
		return err
	}

	// In some cases, we do not have to wait here because the cmd was executed
	// with run(), which already waits. On the contrary, in the case it was
	// executed with start() thus ig.started is true, we need to wait indeed.
	if ig.started {
		err = ig.cmd.Wait()
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

func (ig *IG) StopCmd() error {
	if !ig.started {
		return fmt.Errorf("Warn(%v): trying to stop command but it was not started", ig.cmd)
	}

	if err := ig.kill(); err != nil {
		return err
	}

	ig.started = false
	return nil
}

type option func(*IG)

func WithPath(path string) option {
	return func(ig *IG) {
		ig.path = path
	}
}

func WithImage(image string) option {
	return func(ig *IG) {
		ig.image = image
	}
}

// WithFlags should be in form: "--flag_name=value" or "-shorthand=value"
func WithFlags(flags ...string) option {
	return func(ig *IG) {
		ig.flags = flags
	}
}

// WithEnv vars should be in form: "ENV_VARIABLE_NAME=value"
func WithEnv(env ...string) option {
	return func(ig *IG) {
		ig.env = env
	}
}

func WithStartAndStop() option {
	return func(ig *IG) {
		ig.startAndStop = true
	}
}

// Runs "ig version" to get the version string
func getIgVersionString(path string) string {
	cmd := exec.Command(path, "version")

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		fmt.Printf("getting version from ig: %v", err)
		return ""
	}
	return out.String()
}

func extractIgVersion(str string) semver.Version {
	parsedVersion, err := semver.ParseTolerant(str)
	if err != nil {
		fmt.Printf("parsing version from string[%s]: %v]", str, err)
	}
	return parsedVersion
}

// New creates a new IG configured with the options passed as parameters.
// Supported parameters are:
//
//	WithImage(gadget_image)
//	WithPath(string)
//	WithEnv(...string)
//	WithFlags(...string)
//	WithStartAndStop()
func New(opts ...option) *IG {
	ig := &IG{
		path: "ig",
	}

	for _, opt := range opts {
		opt(ig)
	}

	vstring := getIgVersionString(ig.path)
	ig.version = extractIgVersion(vstring)

	return ig
}

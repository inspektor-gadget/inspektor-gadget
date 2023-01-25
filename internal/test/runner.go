//go:build linux
// +build linux

// Copyright 2022 The Inspektor Gadget authors
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

package test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunnerConfig defines how the runner should behave.
// TODO: We could implement more options like unsharing the network
// namespace, running on a different group ID, etc.
type RunnerConfig struct {
	// User ID to run under
	UID int
}

// RunnerInfo contains information about the runner and it's used by the
// tests to verify that the generated events have the correct value for
// fields like PID, UID and MountNsID.
type RunnerInfo struct {
	Pid       int
	Tid       int
	Comm      string
	UID       int
	MountNsID uint64
}

// Runner is a helper type to execute tests in different conditions. It
// creates a go routine that is executed in a different mount namespace,
// user ID, etc. to simulate events hapenning inside containers.
type Runner struct {
	config *RunnerConfig

	tasks   chan func() error
	replies chan error
	Info    *RunnerInfo
}

func NewRunner(config *RunnerConfig) (*Runner, error) {
	if config == nil {
		config = &RunnerConfig{}
	}
	r := &Runner{
		config:  config,
		tasks:   make(chan func() error),
		replies: make(chan error),
	}

	go r.runLoop()

	if err := <-r.replies; err != nil {
		r.Close()
		return nil, err
	}

	return r, nil
}

func (r *Runner) Run(f func() error) error {
	r.tasks <- f
	return <-r.replies
}

func (r *Runner) Close() {
	if r.tasks != nil {
		close(r.tasks)
		r.tasks = nil
	}
	if r.replies != nil {
		close(r.replies)
		r.replies = nil
	}
}

func (r *Runner) runLoop() {
	// Don't switch thread in the following code
	runtime.LockOSThread()
	// We aren't calling runtime.UnlockOSThread() to let this thread
	// die because some changes are not recoverable, like switching
	// to a non-root UID.

	mountnsid, err := createMntNamespace()
	if err != nil {
		r.replies <- fmt.Errorf("creating mount namespace: %w", err)
		return
	}

	if r.config.UID != 0 {
		// syscall.Setuid() can't be used here because it'll
		// change the UID of all threads and we only need to
		// change the one of this thread.
		// https://github.com/golang/go/commit/d1b1145cace8b968307f9311ff611e4bb810710c
		_, _, errno := syscall.Syscall(syscall.SYS_SETUID, uintptr(r.config.UID), 0, 0)
		if errno != 0 {
			r.replies <- fmt.Errorf("setting uid: %w", err)
			return
		}
	}

	comm, err := os.Executable()
	if err != nil {
		r.replies <- fmt.Errorf("getting current executable: %w", err)
		return
	}

	r.Info = &RunnerInfo{
		Pid:       os.Getpid(),
		Tid:       unix.Gettid(),
		Comm:      filepath.Base(comm),
		UID:       r.config.UID,
		MountNsID: mountnsid,
	}

	// Indicate it's ready to process tasks
	r.replies <- nil

	for task := range r.tasks {
		r.replies <- task()
	}
}

func createMntNamespace() (uint64, error) {
	if err := unix.Unshare(syscall.CLONE_NEWNS); err != nil {
		return 0, err
	}
	return getMntNamespaceInode()
}

func getMntNamespaceInode() (uint64, error) {
	pid := os.Getpid()
	tid := unix.Gettid()

	fileinfo, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d/ns/mnt", pid, tid))
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

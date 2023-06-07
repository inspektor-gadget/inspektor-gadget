// Copyright 2023 The Inspektor Gadget authors
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

// Package bpfiterns reads a ebpf iterator in a different namespace.
package bpfiterns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	_ "github.com/godbus/dbus/v5"
	"github.com/google/uuid"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

var isHostPidNs bool

func init() {
	selfFileInfo, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return
	}
	selfStat, ok := selfFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	systemdFileInfo, err := os.Stat(fmt.Sprintf("%s/1/ns/pid", host.HostProcFs))
	if err != nil {
		return
	}
	systemdStat, ok := systemdFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	isHostPidNs = selfStat.Ino == systemdStat.Ino
}

// Read reads the iterator in the host pid namespace.
// It will test if the current pid namespace is the host pid namespace.
func Read(iter *link.Iter) ([]byte, error) {
	if isHostPidNs {
		return ReadOnCurrentPidNs(iter)
	} else {
		return ReadOnHostPidNs(iter)
	}
}

// ReadOnCurrentPidNs reads the iterator in the current pid namespace.
func ReadOnCurrentPidNs(iter *link.Iter) ([]byte, error) {
	file, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("open BPF iterator: %w", err)
	}
	defer file.Close()
	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read BPF iterator: %w", err)
	}
	return buf, err
}

// ReadOnHostPidNs reads the iterator in the host pid namespace.
// It does so by pinning the iterator in a temporary directory in the host bpffs,
// and then creating a systemd service that will read the iterator and write it
// to a temporary pipe. The pipe is then read and returned.
func ReadOnHostPidNs(iter *link.Iter) ([]byte, error) {
	selfPidOnHost, err := os.Readlink(filepath.Join(host.HostProcFs, "self"))
	if err != nil {
		return nil, fmt.Errorf("readlink /proc/self: %w", err)
	}
	if selfPidOnHost == "" {
		return nil, fmt.Errorf("empty /proc/self symlink")
	}

	// Create a temporary directory in the host bpffs
	bpfFS := "/sys/fs/bpf"
	tmpPinDir, err := os.MkdirTemp(host.HostRoot+bpfFS, "ig-iter-")
	if err != nil {
		return nil, fmt.Errorf("creating temporary directory in bpffs: %w", err)
	}
	defer os.RemoveAll(tmpPinDir)

	// Prepare the pin path from the container and host point of view
	pinPath := filepath.Join(tmpPinDir, "iter")
	pinPathHost := filepath.Join(bpfFS, filepath.Base(tmpPinDir), "iter")

	err = iter.Pin(pinPath)
	if err != nil {
		return nil, fmt.Errorf("pinning iterator: %w", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating pipe: %w", err)
	}
	writerPath := fmt.Sprintf("/proc/%s/fd/%d", selfPidOnHost, w.Fd())

	var buf []byte
	var errReader error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		stdoutReader := bufio.NewReader(r)
		// ReadAll will block until the write-side of the pipe is closed in both processes
		// (the systemd service and this process)
		buf, errReader = io.ReadAll(stdoutReader)
		r.Close()
		wg.Done()
	}()

	conn, err := systemdDbus.NewSystemdConnectionContext(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("connecting to systemd: %w", err)
	}
	defer conn.Close()

	runID := uuid.New().String()[:8]
	unitName := fmt.Sprintf("ig-%s.service", runID)

	statusChan := make(chan string, 1)
	properties := []systemdDbus.Property{
		systemdDbus.PropDescription("Inspektor Gadget job on host pidns"),
		// Type=oneshot ensures that StartTransientUnitContext will only return "done" when the job is done
		systemdDbus.PropType("oneshot"),
		systemdDbus.PropExecStart([]string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("cat %s > %s", pinPathHost, writerPath),
		}, true),
	}

	_, err = conn.StartTransientUnitContext(context.TODO(),
		unitName, "fail", properties, statusChan)
	if err != nil {
		return nil, fmt.Errorf("starting transient unit: %w", err)
	}
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	select {
	case s := <-statusChan:
		close(statusChan)

		// Close writer first: this will unblock the go routine reading from the pipe
		w.Close()
		wg.Wait()

		if errReader != nil {
			return nil, fmt.Errorf("reading from pipe: %w", errReader)
		}

		// "done" indicates successful execution of a job
		// See https://pkg.go.dev/github.com/coreos/go-systemd/v22/dbus#Conn.StartUnit
		if s != "done" {
			conn.ResetFailedUnitContext(context.TODO(), unitName)

			return nil, fmt.Errorf("creating systemd unit `%s`: got `%s`", unitName, s)
		}
	case <-timeout.C:
		w.Close()
		wg.Wait()

		conn.ResetFailedUnitContext(context.TODO(), unitName)
		return nil, errors.New("timeout waiting for systemd to create " + unitName)
	}

	return buf, nil
}

// Copyright 2021 The Inspektor Gadget authors
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

package runcfanotify

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type EventType int

const (
	EVENT_TYPE_ADD_CONTAINER EventType = iota
	EVENT_TYPE_REMOVE_CONTAINER
)

// ContainerEvent is the notification for container creation or termination
type ContainerEvent struct {
	// Type is whether the container was added or removed
	Type EventType

	// ContainerID is the container id, typically a 64 hexadecimal string
	ContainerID string

	// ContainerPID is the process id of the container
	ContainerPID uint32

	// Container's configuration is the config.json from the OCI runtime
	// spec
	ContainerConfig *ocispec.Spec
}

type RuncNotifyFunc func(notif ContainerEvent)

type RuncNotifier struct {
	runcBinaryNotify *fanotify.NotifyFD
	callback         RuncNotifyFunc

	// containers is the set of containers that are being watched for
	// termination. This prevents duplicate calls to
	// AddWatchContainerTermination.
	//
	// Keys: Container ID
	// Value: dummy struct
	containers map[string]struct{}
	mu         sync.Mutex
}

// runcPaths is the list of paths where runc could be installed. Depending on
// the Linux distribution, it could be in different locations.
//
// When this package is executed in a container, it looks at the /host volume.
var runcPaths = []string{
	"/usr/bin/runc",
	"/usr/sbin/runc",
	"/usr/local/sbin/runc",
	"/run/torcx/unpack/docker/bin/runc",

	"/host/usr/bin/runc",
	"/host/usr/sbin/runc",
	"/host/usr/local/sbin/runc",
	"/host/run/torcx/unpack/docker/bin/runc",
}

// Supported detects if RuncNotifier is supported in the current environment
func Supported() bool {
	// Test that runc is available
	runcFound := false
	for _, path := range runcPaths {
		if _, err := os.Stat(path); err == nil {
			runcFound = true
			break
		}
	}
	if !runcFound {
		return false
	}

	// Test that pidfd_open() is available
	pidfd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(os.Getpid()), 0, 0)
	if errno != 0 {
		return false
	}
	unix.Close(int(pidfd))
	return true
}

// NewRuncNotifier uses fanotify to detect when runc containers are created
// or terminated, and call the callback on such event.
//
// Limitations:
// - runc must be installed in one of the paths listed by runcPaths
// - Linux >= 5.3 (for pidfd_open)
func NewRuncNotifier(callback RuncNotifyFunc) (*RuncNotifier, error) {
	n := &RuncNotifier{
		callback:   callback,
		containers: make(map[string]struct{}),
	}

	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC

	runcBinaryNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return nil, err
	}
	n.runcBinaryNotify = runcBinaryNotify

	for _, file := range runcPaths {
		err = runcBinaryNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, file)
		if err == nil {
			log.Debugf("Checking %q: done", file)
		} else {
			log.Debugf("Checking %q: %s", file, err)
		}
	}

	go n.watchRunc()

	return n, nil
}

func commFromPid(pid int) string {
	comm, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSuffix(string(comm), "\n")
}

func cmdlineFromPid(pid int) []string {
	cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return strings.Split(string(cmdline), "\x00")
}

// AddWatchContainerTermination watches a container for termination and
// generates an event on the notifier. This is automatically called for new
// containers detected by RuncNotifier, but it can also be called for
// containers detected externally such as initial containers.
func (n *RuncNotifier) AddWatchContainerTermination(containerID string, containerPID int) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.containers[containerID]; ok {
		// This container is already being watched for termination
		return nil
	}
	n.containers[containerID] = struct{}{}

	pidfd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(containerPID), 0, 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_open returned %v", errno)
	}

	go n.watchContainerTermination(containerID, containerPID, int(pidfd))
	return nil
}

func (n *RuncNotifier) watchContainerTermination(containerID string, containerPID int, pidfd int) {
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.containers, containerID)
	}()

	defer unix.Close(pidfd)

	for {
		fds := []unix.PollFd{
			{
				Fd:      int32(pidfd),
				Events:  unix.POLLIN,
				Revents: 0,
			},
		}
		count, err := unix.Poll(fds, -1)
		if err == nil && count == 1 {
			n.callback(ContainerEvent{
				Type:         EVENT_TYPE_REMOVE_CONTAINER,
				ContainerID:  containerID,
				ContainerPID: uint32(containerPID),
			})
			return
		}
	}
}

func (n *RuncNotifier) watchPidFileIterate(pidFileDirNotify *fanotify.NotifyFD, bundleDir string, pidFile string, pidFileDir string) (bool, error) {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use
	// it here because ResponseAllow would not be called.
	data, err := pidFileDirNotify.GetEvent()
	if err != nil {
		return false, fmt.Errorf("%w", err)
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return false, nil
	}

	// Don't leak the fd received by GetEvent
	// Cannot use data.Close() and data.File() for the same data: the file
	// would be closed twice:
	// 1. data.Close() -> closed directly with unix.Close()
	// 2. data.File()  -> closed indirectly by os.File's finalizer
	dataFile := data.File()
	defer dataFile.Close()

	if !data.MatchMask(unix.FAN_ACCESS_PERM) {
		// This should not happen: FAN_ACCESS_PERM is the only mask Marked
		return false, fmt.Errorf("fanotify: unknown event on runc: mask=%d pid=%d", data.Mask, data.Pid)
	}

	// This unblocks whoever is accessing the pidfile
	defer pidFileDirNotify.ResponseAllow(data)

	pid := data.GetPID()

	// Skip events triggered by ourselves
	if pid == os.Getpid() {
		return false, nil
	}

	path, err := data.GetPath()
	if err != nil {
		return false, err
	}
	if path != pidFile {
		return false, nil
	}

	pidFileContent, err := ioutil.ReadAll(dataFile)
	if err != nil {
		return false, err
	}
	if len(pidFileContent) == 0 {
		return false, fmt.Errorf("empty pid file")
	}
	containerPID, err := strconv.Atoi(string(pidFileContent))
	if err != nil {
		return false, err
	}

	// Unfortunately, Linux 5.4 doesn't respect ignore masks
	// See fix in Linux 5.9:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	// Workaround: remove parent mask. We don't need it anymore :)
	err = pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE, unix.FAN_ACCESS_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, pidFileDir)
	if err != nil {
		return false, nil
	}

	bundleConfigJson, err := ioutil.ReadFile(filepath.Join(bundleDir, "config.json"))
	if err != nil {
		return false, err
	}
	containerConfig := &ocispec.Spec{}
	err = json.Unmarshal(bundleConfigJson, containerConfig)
	if err != nil {
		return false, err
	}

	containerID := filepath.Base(filepath.Clean(bundleDir))

	err = n.AddWatchContainerTermination(containerID, containerPID)
	if err != nil {
		log.Errorf("runc fanotify: container %s with pid %d terminated before we could watch it: %s", containerID, containerPID, err)
		return true, nil
	}

	n.callback(ContainerEvent{
		Type:            EVENT_TYPE_ADD_CONTAINER,
		ContainerID:     containerID,
		ContainerPID:    uint32(containerPID),
		ContainerConfig: containerConfig,
	})
	return true, nil
}

func (n *RuncNotifier) monitorRuncInstance(bundleDir string, pidFile string) error {
	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC

	pidFileDirNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return err
	}

	// The pidfile does not exist yet, so we cannot monitor it directly.
	// Instead we monitor its parent directory with FAN_EVENT_ON_CHILD to
	// get events on the directory's children.
	pidFileDir := filepath.Dir(pidFile)
	err = pidFileDirNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_ACCESS_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, pidFileDir)
	if err != nil {
		pidFileDirNotify.File.Close()
		return fmt.Errorf("cannot mark %s: %w", bundleDir, err)
	}

	// watchPidFileIterate() will read config.json and it might be in the
	// same directory as the pid file. To avoid getting events unrelated to
	// the pidfile, add an ignore mask.
	//
	// This is best effort because the ignore mask is unfortunately not
	// respected until a fix in Linux 5.9:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	configJsonPath := filepath.Join(bundleDir, "config.json")
	err = pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJsonPath)
	if err != nil {
		pidFileDirNotify.File.Close()
		return fmt.Errorf("cannot ignore %s: %w", configJsonPath, err)
	}

	go func() {
		for {
			stop, err := n.watchPidFileIterate(pidFileDirNotify, bundleDir, pidFile, pidFileDir)
			if err != nil {
				log.Errorf("error: %v\n", err)
			}
			if stop {
				pidFileDirNotify.File.Close()
				return
			}
		}
	}()

	return nil
}

func (n *RuncNotifier) watchRunc() {
	for {
		stop, err := n.watchRuncIterate()
		if err != nil {
			log.Errorf("error: %v\n", err)
		}
		if stop {
			n.runcBinaryNotify.File.Close()
			return
		}
	}
}

func (n *RuncNotifier) watchRuncIterate() (bool, error) {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use it here
	// because ResponseAllow would not be called.
	data, err := n.runcBinaryNotify.GetEvent()
	if err != nil {
		return true, fmt.Errorf("%w", err)
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return false, nil
	}

	// Don't leak the fd received by GetEvent
	dataFile := data.File()
	defer dataFile.Close()

	if !data.MatchMask(unix.FAN_OPEN_EXEC_PERM) {
		// This should not happen: FAN_OPEN_EXEC_PERM is the only mask Marked
		return false, fmt.Errorf("fanotify: unknown event on runc: mask=%d pid=%d", data.Mask, data.Pid)
	}

	// This unblocks the execution
	defer n.runcBinaryNotify.ResponseAllow(data)

	pid := data.GetPID()

	// Skip events triggered by ourselves
	if pid == os.Getpid() {
		return false, nil
	}

	// runc is executing itself with unix.Exec(), so fanotify receives two
	// FAN_OPEN_EXEC_PERM events:
	//   1. from containerd-shim (or similar)
	//   2. from runc, by this re-execution.
	// This filter skips the first one and handles the second one.
	if commFromPid(pid) != "runc" {
		return false, nil
	}

	// Parse runc command line
	cmdlineArr := cmdlineFromPid(pid)
	createFound := false
	bundleDir := ""
	pidFile := ""
	for i := 0; i < len(cmdlineArr); i++ {
		if cmdlineArr[i] == "create" {
			createFound = true
			continue
		}
		if cmdlineArr[i] == "--bundle" && i+1 < len(cmdlineArr) {
			i++
			bundleDir = cmdlineArr[i]
			continue
		}
		if cmdlineArr[i] == "--pid-file" && i+1 < len(cmdlineArr) {
			i++
			pidFile = cmdlineArr[i]
			continue
		}
	}

	if createFound && bundleDir != "" && pidFile != "" {
		err := n.monitorRuncInstance(bundleDir, pidFile)
		if err != nil {
			log.Errorf("error: %v\n", err)
		}
	}

	return false, nil
}

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
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type EventType int

const (
	EventTypeAddContainer EventType = iota
	EventTypeRemoveContainer
)

var hostRoot string

func init() {
	hostRoot = os.Getenv("HOST_ROOT")
}

// ContainerEvent is the notification for container creation or termination
type ContainerEvent struct {
	// Type is whether the container was added or removed
	Type EventType

	// ContainerID is the container id, typically a 64 hexadecimal string
	ContainerID string

	// ContainerName is the container name, typically two words with an underscore
	ContainerName string

	// ContainerPID is the process id of the container
	ContainerPID uint32

	// Container's configuration is the config.json from the OCI runtime
	// spec
	ContainerConfig *ocispec.Spec

	// Bundle is the directory containing the config.json from the OCI
	// runtime spec
	// See https://github.com/opencontainers/runtime-spec/blob/main/bundle.md
	Bundle string
}

type RuncNotifyFunc func(notif ContainerEvent)

type runcContainer struct {
	id    string
	pid   int
	pidfd int
}

type futureContainer struct {
	id        string
	name      string
	bundleDir string
	pidFile   string
}

type RuncNotifier struct {
	runcBinaryNotify *fanotify.NotifyFD
	callback         RuncNotifyFunc

	// containers is the set of containers that are being watched for
	// termination. This prevents duplicate calls to
	// AddWatchContainerTermination.
	//
	// Keys: Container ID
	containers   map[string]*runcContainer
	containersMu sync.Mutex

	// futureContainers is the set of containers that are detected before
	// oci-runtime (runc/crun) creates the container e.g. detected via conmon
	//
	// Keys: Container ID
	futureContainers map[string]*futureContainer
	futureMu         sync.Mutex

	// set to true when RuncNotifier is closed
	closed bool

	wg sync.WaitGroup

	pipeFds []int
}

// runcPaths is the list of paths where runc could be installed. Depending on
// the Linux distribution, it could be in different locations.
//
// When this package is executed in a container, it prepends the
// HOST_ROOT env variable to the path.
var runcPaths = []string{
	"/usr/bin/runc",
	"/usr/sbin/runc",
	"/usr/local/sbin/runc",
	"/usr/lib/cri-o-runc/sbin/runc",
	"/run/torcx/unpack/docker/bin/runc",
	"/usr/bin/crun",
}

// true if the SYS_PIDFD_OPEN syscall is available
var pidfdOpenAvailable bool

func init() {
	pid := uintptr(os.Getpid())
	pidfd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, pid, 0, 0)
	if errno == unix.ENOSYS {
		log.Debug("SYS_PIDFD_OPEN is not available")
		pidfdOpenAvailable = false
		return
	}

	if errno != 0 {
		pidfdOpenAvailable = false
		log.Debugf("probing SYS_PIDFD_OPEN failed with: %s", errno)
		return
	}

	unix.Close(int(pidfd))

	log.Debug("SYS_PIDFD_OPEN is available")
	pidfdOpenAvailable = true
}

// initFanotify initializes the fanotify API with the flags we need
func initFanotify() (*fanotify.NotifyFD, error) {
	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS | unix.FAN_NONBLOCK)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return fanotify.Initialize(fanotifyFlags, openFlags)
}

// Supported detects if RuncNotifier is supported in the current environment
func Supported() bool {
	notifier, err := NewRuncNotifier(func(notif ContainerEvent) {})
	if notifier != nil {
		notifier.Close()
	}
	if err != nil {
		log.Debugf("Runcfanotify: not supported: %s", err)
	}
	return err == nil
}

// NewRuncNotifier uses fanotify to detect when runc containers are created
// or terminated, and call the callback on such event.
//
// Limitations:
// - runc must be installed in one of the paths listed by runcPaths
func NewRuncNotifier(callback RuncNotifyFunc) (*RuncNotifier, error) {
	n := &RuncNotifier{
		callback:         callback,
		containers:       make(map[string]*runcContainer),
		futureContainers: make(map[string]*futureContainer),
		pipeFds:          []int{-1, -1},
	}

	runcBinaryNotify, err := initFanotify()
	if err != nil {
		return nil, err
	}
	n.runcBinaryNotify = runcBinaryNotify

	runcMonitored := false

	for _, r := range runcPaths {
		runcPath := filepath.Join(hostRoot, r)

		log.Debugf("Runcfanotify: trying runc at %s", runcPath)

		if _, err := os.Stat(runcPath); errors.Is(err, os.ErrNotExist) {
			log.Debugf("Runcfanotify: runc at %s not found", runcPath)
			continue
		}

		if err := runcBinaryNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, runcPath); err != nil {
			log.Warnf("Runcfanotify: failed to fanotify mark: %s", err)
			continue
		}
		runcMonitored = true
	}

	if !runcMonitored {
		runcBinaryNotify.File.Close()
		return nil, errors.New("no runc instance can be monitored with fanotify")
	}

	n.wg.Add(2)
	if pidfdOpenAvailable {
		if err := unix.Pipe2(n.pipeFds, unix.O_NONBLOCK); err != nil {
			runcBinaryNotify.File.Close()
			return nil, fmt.Errorf("creating pipe: %w", err)
		}

		go n.watchContainersTermination()
	} else {
		go n.watchContainersTerminationFallback()
	}
	go n.watchRunc()

	return n, nil
}

func commFromPid(pid int) string {
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSuffix(string(comm), "\n")
}

func cmdlineFromPid(pid int) []string {
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return strings.Split(string(cmdline), "\x00")
}

// AddWatchContainerTermination watches a container for termination and
// generates an event on the notifier. This is automatically called for new
// containers detected by RuncNotifier, but it can also be called for
// containers detected externally such as initial containers.
func (n *RuncNotifier) AddWatchContainerTermination(containerID string, containerPID int) error {
	n.containersMu.Lock()
	defer n.containersMu.Unlock()

	if _, ok := n.containers[containerID]; ok {
		// This container is already being watched for termination
		return nil
	}

	n.containers[containerID] = &runcContainer{
		id:  containerID,
		pid: containerPID,
	}

	if !pidfdOpenAvailable {
		return nil
	}

	pidfd, _, errno := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(containerPID), 0, 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_open returned %w", errno)
	}

	n.containers[containerID].pidfd = int(pidfd)

	n.awakeWatchContainersTermination()

	return nil
}

// awakeWatchContainersTermination writes to the pipe so
// watchContainersTermination() unblocks waiting on poll() and can
// update the list of the watched containers or return if the
// runcnotifier instance was closed
func (n *RuncNotifier) awakeWatchContainersTermination() {
	if n.pipeFds[1] != -1 {
		f := []byte{0}
		unix.Write(n.pipeFds[1], f)
	}
}

// watchContainerTermination waits until the container terminates using
// pidfd_open (Linux >= 5.3), then sends a notification.
func (n *RuncNotifier) watchContainersTermination() {
	// Index used in the array of file descriptor we monitor
	const pipeIndex = 0

	defer n.wg.Done()

	pipeFdR := n.pipeFds[0]

	for {
		if n.closed {
			// close all pidfds
			for _, c := range n.containers {
				unix.Close(c.pidfd)
			}
			return
		}

		n.containersMu.Lock()

		fds := make([]unix.PollFd, len(n.containers)+1)
		// array to create a relation between the fd position and the container
		containersByIndex := make([]*runcContainer, len(n.containers)+1)

		i := 0

		fds[pipeIndex].Fd = int32(pipeFdR)
		fds[pipeIndex].Events = unix.POLLIN

		for _, c := range n.containers {
			fds[i+1].Fd = int32(c.pidfd)
			fds[i+1].Events = unix.POLLIN

			containersByIndex[i+1] = c
			i++
		}
		n.containersMu.Unlock()

		count, err := unix.Poll(fds, -1)
		if err != nil && !errors.Is(err, unix.EINTR) {
			log.Errorf("error polling pidfds: %s", err)
			return
		}

		if count == 0 {
			continue
		}

		for i, fd := range fds {
			if fd.Revents == 0 {
				continue
			}

			// if this is the pipe, read and continue processing
			if i == pipeIndex {
				r := make([]byte, 1)
				unix.Read(int(fd.Fd), r)
				continue
			}

			c := containersByIndex[i]

			n.callback(ContainerEvent{
				Type:         EventTypeRemoveContainer,
				ContainerID:  c.id,
				ContainerPID: uint32(c.pid),
			})

			unix.Close(c.pidfd)

			n.containersMu.Lock()
			delete(n.containers, c.id)
			n.containersMu.Unlock()
		}
	}
}

// watchContainerTerminationFallback waits until the container terminates
// *without* using pidfd_open so it works on older kernels, then sends a notification.
func (n *RuncNotifier) watchContainersTerminationFallback() {
	defer n.wg.Done()

	for {
		if n.closed {
			return
		}
		time.Sleep(1 * time.Second)

		for _, c := range n.containers {
			process, err := os.FindProcess(c.pid)
			if err == nil {
				// no signal is sent: signal 0 just check for the
				// existence of the process
				err = process.Signal(syscall.Signal(0))
			}

			if err != nil {
				n.callback(ContainerEvent{
					Type:         EventTypeRemoveContainer,
					ContainerID:  c.id,
					ContainerPID: uint32(c.pid),
				})

				n.containersMu.Lock()
				delete(n.containers, c.id)
				n.containersMu.Unlock()
			}
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
	defer data.Close()
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
	path = filepath.Join(hostRoot, path)

	// Consider files identical if they have the same device/inode,
	// even if the paths differ due to symlinks (for example,
	// the event's path is /run/... but the runc --pid-file argument
	// uses /var/run/..., where /var/run is a symlink to /run).
	filesAreIdentical, err := checkFilesAreIdentical(path, pidFile)
	if err != nil {
		return false, err
	} else if !filesAreIdentical {
		return false, nil
	}

	pidFileContent, err := io.ReadAll(dataFile)
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

	bundleConfigJSON, err := os.ReadFile(filepath.Join(bundleDir, "config.json"))
	if err != nil {
		return false, err
	}
	containerConfig := &ocispec.Spec{}
	err = json.Unmarshal(bundleConfigJSON, containerConfig)
	if err != nil {
		return false, err
	}

	// cri-o appends userdata to bundleDir,
	// so we trim it here to get the correct containerID
	containerID := filepath.Base(filepath.Clean(strings.TrimSuffix(bundleDir, "userdata")))

	err = n.AddWatchContainerTermination(containerID, containerPID)
	if err != nil {
		log.Errorf("runc fanotify: container %s with pid %d terminated before we could watch it: %s", containerID, containerPID, err)
		return true, nil
	}

	if containerPID > math.MaxUint32 {
		log.Errorf("Container PID (%d) exceeds math.MaxUint32 (%d)", containerPID, math.MaxUint32)
		return true, nil
	}

	var containerName string
	if fc := n.lookupFutureContainer(containerID); fc != nil {
		containerName = fc.name
	}

	n.callback(ContainerEvent{
		Type:            EventTypeAddContainer,
		ContainerID:     containerID,
		ContainerPID:    uint32(containerPID),
		ContainerConfig: containerConfig,
		Bundle:          bundleDir,
		ContainerName:   containerName,
	})

	return true, nil
}

func checkFilesAreIdentical(path1, path2 string) (bool, error) {
	f1, err := os.Stat(path1)
	if err != nil {
		return false, err
	}

	f2, err := os.Stat(path2)
	if err != nil {
		return false, err
	}

	return os.SameFile(f1, f2), nil
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
		return fmt.Errorf("cannot mark %s: %w", pidFileDir, err)
	}

	// watchPidFileIterate() will read config.json and it might be in the
	// same directory as the pid file. To avoid getting events unrelated to
	// the pidfile, add an ignore mask.
	//
	// This is best effort because the ignore mask is unfortunately not
	// respected until a fix in Linux 5.9:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	configJSONPath := filepath.Join(bundleDir, "config.json")
	err = pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJSONPath)
	if err != nil {
		pidFileDirNotify.File.Close()
		return fmt.Errorf("cannot ignore %s: %w", configJSONPath, err)
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer pidFileDirNotify.File.Close()
		for {
			stop, err := n.watchPidFileIterate(pidFileDirNotify, bundleDir, pidFile, pidFileDir)
			if n.closed {
				return
			}
			if err != nil {
				log.Warnf("error watching pid: %v\n", err)
				return
			}
			if stop {
				return
			}
		}
	}()

	return nil
}

func (n *RuncNotifier) watchRunc() {
	defer n.wg.Done()

	for {
		stop, err := n.watchRuncIterate()
		if n.closed {
			n.runcBinaryNotify.File.Close()
			return
		}
		if err != nil {
			log.Errorf("error watching runc: %v\n", err)
		}
		if stop {
			n.runcBinaryNotify.File.Close()
			return
		}
	}
}

func (n *RuncNotifier) parseConmonCmdline(cmdlineArr []string) {
	if path.Base(cmdlineArr[0]) != "conmon" {
		return
	}

	// Parse conmon command line
	containerName := ""
	containerID := ""
	bundleDir := ""
	pidFile := ""
	conmonFound := false

	conmonFound = true
	for i := 0; i < len(cmdlineArr); i++ {
		verb := cmdlineArr[i]
		arg := ""
		if i+1 < len(cmdlineArr) {
			arg = cmdlineArr[i+1]
		}
		switch verb {
		case "-n", "--name":
			containerName = arg
			i++
		case "-c", "--cid":
			containerID = arg
			i++
		case "-b", "--bundle":
			bundleDir = arg
			i++
		case "-p", "--container-pidfile":
			pidFile = arg
			i++
		}
	}

	if !conmonFound || containerName == "" || containerID == "" || bundleDir == "" || pidFile == "" {
		return
	}

	n.futureMu.Lock()
	n.futureContainers[containerID] = &futureContainer{
		id:        containerID,
		pidFile:   pidFile,
		bundleDir: bundleDir,
		name:      containerName,
	}
	n.futureMu.Unlock()
}

func (n *RuncNotifier) parseOCIRuntime(comm string, cmdlineArr []string) {
	// Parse oci-runtime (runc/crun) command line
	createFound := false
	startFound := false
	containerID := ""
	bundleDir := ""
	pidFile := ""

	for i := 0; i < len(cmdlineArr); i++ {
		if cmdlineArr[i] == "create" {
			createFound = true
			continue
		}
		if cmdlineArr[i] == "start" {
			startFound = true
			continue
		}
		if cmdlineArr[i] == "--bundle" && i+1 < len(cmdlineArr) {
			i++
			bundleDir = filepath.Join(hostRoot, cmdlineArr[i])
			continue
		}
		if cmdlineArr[i] == "--pid-file" && i+1 < len(cmdlineArr) {
			i++
			pidFile = filepath.Join(hostRoot, cmdlineArr[i])
			continue
		}
		if cmdlineArr[i] != "" {
			containerID = cmdlineArr[i]
		}
	}

	if comm == "runc" && createFound && bundleDir != "" && pidFile != "" {
		err := n.monitorRuncInstance(bundleDir, pidFile)
		if err != nil {
			log.Errorf("error monitoring runc instance: %v\n", err)
		}
	}

	if comm == "crun" && startFound && containerID != "" {
		fc := n.lookupFutureContainer(containerID)
		if fc == nil {
			log.Warnf("cannot lookup container for %s\n", containerID)
			return
		}
		bundleConfigJSON, err := os.ReadFile(filepath.Join(fc.bundleDir, "config.json"))
		if err != nil {
			log.Errorf("error reading bundle config: %v\n", err)
			return
		}
		containerConfig := &ocispec.Spec{}
		err = json.Unmarshal(bundleConfigJSON, containerConfig)
		if err != nil {
			log.Errorf("error unmarshaling bundle config: %v\n", err)
			return
		}

		pidFileContent, err := os.ReadFile(fc.pidFile)
		if err != nil {
			log.Errorf("error reading pid file: %v\n", err)
			return
		}
		if len(pidFileContent) == 0 {
			log.Errorf("empty pid file")
			return
		}
		containerPID, err := strconv.Atoi(string(pidFileContent))
		if err != nil {
			log.Errorf("error parsing pid file: %v\n", err)
			return
		}

		n.callback(ContainerEvent{
			Type:            EventTypeAddContainer,
			ContainerID:     containerID,
			ContainerPID:    uint32(containerPID),
			ContainerConfig: containerConfig,
			Bundle:          bundleDir,
			ContainerName:   fc.name,
		})
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
	defer data.Close()

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
	comm := commFromPid(pid)
	cmdlineArr := cmdlineFromPid(pid)

	if len(cmdlineArr) == 0 {
		return false, nil
	}

	switch comm {
	case "conmon":
		// conmon is a special case because it is not a child of the container
		// Also, the calling sequence is podman -> conmon -> runc
		n.parseConmonCmdline(cmdlineArr)
	case "runc", "crun":
		n.parseOCIRuntime(comm, cmdlineArr)
	default:
		return false, nil
	}

	return false, nil
}

func (n *RuncNotifier) Close() {
	n.closed = true
	n.awakeWatchContainersTermination()
	for _, fd := range n.pipeFds {
		if fd != -1 {
			unix.Close(fd)
		}
	}
	n.runcBinaryNotify.File.Close()
	n.wg.Wait()
}

func (n *RuncNotifier) lookupFutureContainer(id string) *futureContainer {
	n.futureMu.Lock()
	defer n.futureMu.Unlock()
	fc, ok := n.futureContainers[id]
	if !ok {
		return nil
	}
	delete(n.futureContainers, id)
	return fc
}

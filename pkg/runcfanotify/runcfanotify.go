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
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type EventType int

const (
	EventTypeAddContainer EventType = iota
	EventTypeRemoveContainer
)

// ContainerEvent is the notification for container creation or termination
type ContainerEvent struct {
	// Type is whether the container was added or removed
	Type EventType

	// ContainerID is the container id, typically a 64 hexadecimal string
	ContainerID string

	// ContainerName is the container name given by the container runtime,
	// typically two words with an underscore. Notice it might be different from
	// the one given by Kubernetes.
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
	done   chan bool

	wg sync.WaitGroup
}

// runcPaths is the list of paths where runc could be installed. Depending on
// the Linux distribution, it could be in different locations.
//
// When this package is executed in a container, it prepends the
// HOST_ROOT env variable to the path.
var runcPaths = []string{
	"/bin/runc",
	"/usr/bin/runc",
	"/usr/sbin/runc",
	"/usr/local/sbin/runc",
	"/usr/lib/cri-o-runc/sbin/runc",
	"/run/torcx/unpack/docker/bin/runc",
	"/usr/bin/crun",
}

// initFanotify initializes the fanotify API with the flags we need
func initFanotify() (*fanotify.NotifyFD, error) {
	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS | unix.FAN_NONBLOCK)
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return fanotify.Initialize(fanotifyFlags, openFlags)
}

// Supported detects if RuncNotifier is supported in the current environment
func Supported() bool {
	hostPidNs, err := host.IsHostPidNs()
	if err != nil {
		log.Debugf("Runcfanotify: not supported: %s", err)
		return false
	}
	if !hostPidNs {
		log.Debugf("Runcfanotify: not supported: not in host pid namespace")
		return false
	}
	notifier, err := NewRuncNotifier(func(notif ContainerEvent) {})
	if notifier != nil {
		notifier.Close()
	}
	if err != nil {
		log.Warnf("checking if current pid namespace is host pid namespace %s", err)
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
		done:             make(chan bool),
	}

	runcBinaryNotify, err := initFanotify()
	if err != nil {
		return nil, err
	}
	n.runcBinaryNotify = runcBinaryNotify

	runcMonitored := false

	for _, r := range runcPaths {
		runcPath := filepath.Join(host.HostRoot, r)

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

	// Let's try to find runc in some directories under /host before failing.
	if !runcMonitored {
		for _, p := range []string{"/bin", "/usr", "/run"} {
			fullPath := filepath.Join(host.HostRoot, p)
			log.Debugf("Runcfanotify: searching runc in %s", fullPath)

			filepath.WalkDir(fullPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}

				if !d.IsDir() && (d.Name() == "runc" || d.Name() == "crun") {
					if err := runcBinaryNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path); err != nil {
						log.Warnf("Runcfanotify: failed to fanotify mark: %s", err)
						return nil
					}

					log.Infof("Runcfanotify: found runc in %s, please open a PR to add it to runcPaths", path)

					runcMonitored = true

					// golang 1.20 comes with SkipAll which permits stopping the walk
					// here.
					return filepath.SkipDir
				}

				return nil
			})

			if runcMonitored {
				break
			}
		}
	}

	// We did not find it in either runcPaths and some specific directories, it is
	// time to fail.
	if !runcMonitored {
		runcBinaryNotify.File.Close()
		return nil, errors.New("no runc instance can be monitored with fanotify")
	}

	n.wg.Add(2)
	go n.watchContainersTermination()
	go n.watchRunc()

	return n, nil
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

	return nil
}

// watchContainerTermination waits until the container terminates
func (n *RuncNotifier) watchContainersTermination() {
	defer n.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			if n.closed {
				return
			}

			dirEntries, err := os.ReadDir(host.HostProcFs)
			if err != nil {
				log.Errorf("reading /proc: %s", err)
				return
			}
			pids := make(map[int]bool)
			for _, entry := range dirEntries {
				pid, err := strconv.Atoi(entry.Name())
				if err != nil {
					// entry is not a process directory. Ignore.
					continue
				}
				pids[pid] = true
			}

			for _, c := range n.containers {
				if pids[c.pid] {
					// container still running
					continue
				}

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
	path = filepath.Join(host.HostRoot, path)

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
	// Since fanotify masks don't work on Linux 5.4, we could get a
	// notification for an unrelated file before the pid file is created
	// See fix in Linux 5.9:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	// In this case we should not return an error.
	if filepath.Base(path1) != filepath.Base(path2) {
		return false, nil
	}

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
		return fmt.Errorf("marking %s: %w", pidFileDir, err)
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
		return fmt.Errorf("ignoring %s: %w", configJSONPath, err)
	}

	// similar to config.json, we ignore passwd file if it exists
	passwdPath := filepath.Join(bundleDir, "passwd")
	if _, err := os.Stat(passwdPath); !errors.Is(err, os.ErrNotExist) {
		err = pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, passwdPath)
		if err != nil {
			pidFileDirNotify.File.Close()
			return fmt.Errorf("marking passwd path: %w", err)
		}
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
			bundleDir = filepath.Join(host.HostRoot, cmdlineArr[i])
			continue
		}
		if cmdlineArr[i] == "--pid-file" && i+1 < len(cmdlineArr) {
			i++
			pidFile = filepath.Join(host.HostRoot, cmdlineArr[i])
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
		containerPID, err := strconv.ParseUint(string(pidFileContent), 10, 32)
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
	comm := host.GetProcComm(pid)
	cmdlineArr := host.GetProcCmdline(pid)

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
	close(n.done)
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

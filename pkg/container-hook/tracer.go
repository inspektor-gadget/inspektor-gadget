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

// Package containerhook detects when a container is created or terminated.
//
// It uses two mechanisms to detect new containers:
//  1. fanotify with FAN_OPEN_EXEC_PERM.
//  2. ebpf on the sys_enter_execve tracepoint to get the execve arguments.
//
// Using fanotify with FAN_OPEN_EXEC_PERM allows to call a callback function
// while the container is being created. The container is paused until the
// callback function returns.
//
// Using ebpf on the sys_enter_execve tracepoint allows to get the execve
// arguments without the need to read /proc/$pid/cmdline or /proc/$pid/comm.
// Reading /proc/$pid/cmdline is not possible using only fanotify when the
// tracer is not in the same pidns as the process being traced. This is the
// case when Inspektor Gadget is started with hostPID=false.
//
// https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/devel/fanotify-ebpf.png
package containerhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	runtimefinder "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook/runtime-finder"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kfilefields"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types -type record execruntime ./bpf/execruntime.bpf.c -- -I./bpf/

type EventType int

const (
	EventTypeAddContainer EventType = iota
	EventTypeRemoveContainer
)

const (
	defaultContainerPendingTimeout = 15 * time.Second
	defaultContainerCheckInterval  = 10 * time.Second
)

var (
	// How long to wait for a container after a "conmon" or a "runc start" command
	// The values can be overridden by tests.
	containerPendingTimeout = defaultContainerPendingTimeout
	containerCheckInterval  = defaultContainerCheckInterval
)

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

type ContainerNotifyFunc func(notif ContainerEvent)

type watchedContainer struct {
	id  string
	pid int
}

type pendingContainer struct {
	id             string
	bundleDir      string
	configJSONPath string
	pidFile        string
	pidFileDir     string
	timestamp      time.Time
	removeMarks    []func()
}

type futureContainer struct {
	id        string
	name      string
	bundleDir string
	pidFile   string
	timestamp time.Time
}

type ContainerNotifier struct {
	runtimeBinaryNotify *fanotify.NotifyFD
	pidFileDirNotify    *fanotify.NotifyFD
	callback            ContainerNotifyFunc

	// containers is the set of containers that are being watched for
	// termination. This prevents duplicate calls to
	// AddWatchContainerTermination.
	//
	// Keys: Container ID
	containers   map[string]*watchedContainer
	containersMu sync.Mutex

	// futureContainers is the set of containers that are detected before
	// oci-runtime (runc/crun) creates the container e.g. detected via conmon
	//
	// Keys: Container ID
	futureContainers map[string]*futureContainer
	futureMu         sync.Mutex

	// pendingContainers is the set of containers that are created but not yet
	// started (e.g. 'runc create' executed but not yet 'runc start').
	//
	// Keys: pid file
	pendingContainers map[string]*pendingContainer
	pendingMu         sync.Mutex

	objs  execruntimeObjects
	links []link.Link

	// set to true when the notifier is closed is closed
	closed atomic.Bool
	// this channel is used in watchContainersTermination() to avoid having to wait for the
	// ticker to trigger before returning
	done chan bool

	wg sync.WaitGroup
}

var runtimePaths []string = append(
	runtimefinder.RuntimePaths,
	"/usr/bin/conmon",
)

// initFanotify initializes the fanotify API with the flags we need
func initFanotify() (*fanotify.NotifyFD, error) {
	// Flags for the fanotify fd
	var fanotifyFlags uint
	// FAN_REPORT_TID is required so that kretprobe/fsnotify_remove_first_event can report the tid
	fanotifyFlags |= uint(unix.FAN_REPORT_TID)
	// FAN_CLOEXEC is required to avoid leaking the fd to child processes
	fanotifyFlags |= uint(unix.FAN_CLOEXEC)
	// FAN_CLASS_CONTENT is required for perm events such as FAN_OPEN_EXEC_PERM
	fanotifyFlags |= uint(unix.FAN_CLASS_CONTENT)
	// FAN_UNLIMITED_QUEUE is required so we don't miss any events
	fanotifyFlags |= uint(unix.FAN_UNLIMITED_QUEUE)
	// FAN_UNLIMITED_MARKS is required so we can monitor as many pid files as
	// necessary without being restricted by:
	//     sysctl fs.fanotify.max_user_marks
	// With this flag, we don't influence other applications using fanotify
	// (kernel accounting is per-uid),
	fanotifyFlags |= uint(unix.FAN_UNLIMITED_MARKS)
	// FAN_NONBLOCK is required so GetEvent can be interrupted by Close()
	fanotifyFlags |= uint(unix.FAN_NONBLOCK)

	// Flags for the fd installed when reading a fanotify event (e.g. flag for
	// the runc fd or the pid file fd).
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return fanotify.Initialize(fanotifyFlags, openFlags)
}

// Supported detects if RuncNotifier is supported in the current environment
func Supported() bool {
	notifier, err := NewContainerNotifier(func(notif ContainerEvent) {})
	if notifier != nil {
		notifier.Close()
	}
	if err != nil {
		log.Warnf("ContainerNotifier: not supported: %s", err)
	}
	return err == nil
}

// NewContainerNotifier uses fanotify and ebpf to detect when a container is
// created or terminated, and call the callback on such event.
//
// Limitations:
// - the container runtime must be installed in one of the paths listed by runtimePaths
func NewContainerNotifier(callback ContainerNotifyFunc) (*ContainerNotifier, error) {
	n := &ContainerNotifier{
		callback:          callback,
		containers:        make(map[string]*watchedContainer),
		futureContainers:  make(map[string]*futureContainer),
		pendingContainers: make(map[string]*pendingContainer),
		done:              make(chan bool),
	}

	if err := n.install(); err != nil {
		n.Close()
		return nil, err
	}

	return n, nil
}

func (n *ContainerNotifier) installEbpf(fanotifyFd int) error {
	spec, err := loadExecruntime()
	if err != nil {
		return fmt.Errorf("load ebpf program for container-hook: %w", err)
	}

	fanotifyPrivateData, err := kfilefields.ReadPrivateDataFromFd(fanotifyFd)
	if err != nil {
		return fmt.Errorf("reading private data from fanotify fd: %w", err)
	}

	consts := map[string]interface{}{
		"tracer_group": fanotifyPrivateData,
	}
	//nolint:staticcheck
	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}

	if err := spec.LoadAndAssign(&n.objs, &opts); err != nil {
		return fmt.Errorf("loading maps and programs: %w", err)
	}

	// Attach ebpf programs
	l, err := link.Kprobe("fsnotify_remove_first_event", n.objs.IgFaPickE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe fsnotify_remove_first_event: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Kretprobe("fsnotify_remove_first_event", n.objs.IgFaPickX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe fsnotify_remove_first_event: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_execve", n.objs.IgExecveE, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Tracepoint("sched", "sched_process_exec", n.objs.IgSchedExec, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_execve", n.objs.IgExecveX, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	n.links = append(n.links, l)

	return nil
}

func (n *ContainerNotifier) install() error {
	// Start fanotify
	runtimeBinaryNotify, err := initFanotify()
	if err != nil {
		return err
	}
	n.runtimeBinaryNotify = runtimeBinaryNotify

	pidFileDirNotify, err := initFanotify()
	if err != nil {
		return err
	}
	n.pidFileDirNotify = pidFileDirNotify

	// Load, initialize and attach ebpf program
	err = n.installEbpf(runtimeBinaryNotify.Fd)
	if err != nil {
		return err
	}

	// Attach fanotify to various runtime binaries
	runtimeFound := false

	runtimePath := os.Getenv("RUNTIME_PATH")
	if runtimePath != "" {
		log.Debugf("container-hook: trying runtime from RUNTIME_PATH env variable at %s", runtimePath)

		notifiedPath, err := runtimefinder.Notify(runtimePath, host.HostRoot, runtimeBinaryNotify)
		if err != nil {
			return fmt.Errorf("container-hook: notifying %s: %w", runtimePath, err)
		}

		log.Debugf("container-hook: monitoring runtime at %s (originally %s)", notifiedPath, runtimePath)
		runtimeFound = true
	} else {
		for _, r := range runtimePaths {
			log.Debugf("container-hook: trying runtime at %s", r)

			notifiedPath, err := runtimefinder.Notify(r, host.HostRoot, runtimeBinaryNotify)
			if err != nil {
				log.Debugf("container-hook: notifying %s: %v", runtimePath, err)
				continue
			}

			log.Debugf("container-hook: monitoring runtime at %s (originally %s)", notifiedPath, r)
			runtimeFound = true
		}
	}

	if !runtimeFound {
		return fmt.Errorf("no container runtime can be monitored with fanotify. The following paths were tested: %s. You can use the RUNTIME_PATH env variable to specify a custom path. If you are successful doing so, please open a PR to add your custom path to runtimePaths", strings.Join(runtimePaths, ", "))
	}

	n.wg.Add(4)
	go n.watchContainersTermination()
	go n.watchRuntimeBinary()
	go n.watchPendingContainers()
	go n.checkTimeout()

	return nil
}

// AddWatchContainerTermination watches a container for termination and
// generates an event on the notifier. This is automatically called for new
// containers detected by ContainerNotifier, but it can also be called for
// containers detected externally such as initial containers.
func (n *ContainerNotifier) AddWatchContainerTermination(containerID string, containerPID int) error {
	n.containersMu.Lock()
	defer n.containersMu.Unlock()

	if _, ok := n.containers[containerID]; ok {
		// This container is already being watched for termination
		return nil
	}

	n.containers[containerID] = &watchedContainer{
		id:  containerID,
		pid: containerPID,
	}

	return nil
}

// watchContainerTermination waits until the container terminates
func (n *ContainerNotifier) watchContainersTermination() {
	defer n.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			if n.closed.Load() {
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

			n.containersMu.Lock()
			for _, c := range n.containers {
				if pids[c.pid] {
					// container still running
					continue
				}

				if c.pid > math.MaxUint32 {
					log.Errorf("container PID (%d) exceeds math.MaxUint32 (%d)", c.pid, math.MaxUint32)
					return
				}

				go n.callback(ContainerEvent{
					Type:         EventTypeRemoveContainer,
					ContainerID:  c.id,
					ContainerPID: uint32(c.pid),
				})

				delete(n.containers, c.id)
			}
			n.containersMu.Unlock()
		}
	}
}

func (n *ContainerNotifier) watchPidFileIterate() error {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use
	// it here because ResponseAllow would not be called.
	data, err := n.pidFileDirNotify.GetEvent()
	if err != nil {
		return err
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return nil
	}

	// Don't leak the fd received by GetEvent
	defer data.Close()
	dataFile := data.File()
	defer dataFile.Close()

	if !data.MatchMask(unix.FAN_ACCESS_PERM) {
		// This should not happen: FAN_ACCESS_PERM is the only mask Marked
		log.Errorf("fanotify: unknown event on pid file: mask=%d pid=%d", data.Mask, data.Pid)
		return nil
	}

	// This unblocks whoever is accessing the pidfile
	defer n.pidFileDirNotify.ResponseAllow(data)

	path, err := data.GetPath()
	if err != nil {
		log.Errorf("fanotify: could not get path for pid file")
		return nil
	}
	path = filepath.Join(host.HostRoot, path)

	n.pendingMu.Lock()
	var pc *pendingContainer
	for pidFile := range n.pendingContainers {
		// Consider files identical if they have the same device/inode,
		// even if the paths differ due to symlinks (for example,
		// the event's path is /run/... but the runc --pid-file argument
		// uses /var/run/..., where /var/run is a symlink to /run).
		filesAreIdentical, err := checkFilesAreIdentical(path, pidFile)
		if err == nil && filesAreIdentical {
			pc = n.pendingContainers[pidFile]
			delete(n.pendingContainers, pidFile)
			for _, remove := range pc.removeMarks {
				remove()
			}
			break
		}
	}
	n.pendingMu.Unlock()

	if pc == nil {
		return nil
	}

	pidFileContent, err := io.ReadAll(dataFile)
	if err != nil {
		log.Errorf("fanotify: error reading pid file: %s", err)
		return nil
	}
	if len(pidFileContent) == 0 {
		log.Errorf("fanotify: empty pid file")
		return nil
	}
	containerPID, err := strconv.Atoi(string(pidFileContent))
	if err != nil {
		log.Errorf("fanotify: pid file cannot be parsed: %s", err)
		return nil
	}

	bundleConfigJSON, err := os.ReadFile(pc.configJSONPath)
	if err != nil {
		log.Errorf("fanotify: could not read config.json: %s", err)
		return nil
	}
	containerConfig := &ocispec.Spec{}
	err = json.Unmarshal(bundleConfigJSON, containerConfig)
	if err != nil {
		log.Errorf("fanotify: could not unmarshal config.json: %s", err)
		return nil
	}

	err = n.AddWatchContainerTermination(pc.id, containerPID)
	if err != nil {
		log.Errorf("fanotify: container %s with pid %d terminated before we could watch it: %s", pc.id, containerPID, err)
		return nil
	}

	if containerPID > math.MaxUint32 {
		log.Errorf("fanotify: Container PID (%d) exceeds math.MaxUint32 (%d)", containerPID, math.MaxUint32)
		return nil
	}

	var containerName string
	n.futureMu.Lock()
	fc, ok := n.futureContainers[pc.id]
	if ok {
		containerName = fc.name
	}
	delete(n.futureContainers, pc.id)
	n.futureMu.Unlock()

	n.callback(ContainerEvent{
		Type:            EventTypeAddContainer,
		ContainerID:     pc.id,
		ContainerPID:    uint32(containerPID),
		ContainerConfig: containerConfig,
		Bundle:          pc.bundleDir,
		ContainerName:   containerName,
	})

	return nil
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

func (n *ContainerNotifier) monitorRuntimeInstance(bundleDir string, pidFile string) error {
	removeMarks := []func(){}

	// The pidfile does not exist yet, so we cannot monitor it directly.
	// Instead we monitor its parent directory with FAN_EVENT_ON_CHILD to
	// get events on the directory's children.
	pidFileDir := filepath.Dir(pidFile)
	err := n.pidFileDirNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_ACCESS_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, pidFileDir)
	if err != nil {
		return fmt.Errorf("marking %s: %w", pidFileDir, err)
	}

	removeMarks = append(removeMarks, func() {
		_ = n.pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE, unix.FAN_ACCESS_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, pidFileDir)
	})

	// watchPidFileIterate() will read config.json and it might be in the
	// same directory as the pid file. To avoid getting events unrelated to
	// the pidfile, add an ignore mask.
	//
	// This is best-effort to reduce noise: Linux < 5.9 doesn't respect ignore
	// masks on files when the parent directory is the object being watched:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	configJSONPath := filepath.Join(bundleDir, "config.json")
	if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
		// podman might install config.json in the userdata directory
		configJSONPath = filepath.Join(bundleDir, "userdata", "config.json")
		if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config not found at %s", configJSONPath)
		}
	}
	err = n.pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJSONPath)
	if err != nil {
		return fmt.Errorf("marking %s: %w", configJSONPath, err)
	}

	removeMarks = append(removeMarks, func() {
		_ = n.pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJSONPath)
	})

	// This is best-effort to reduce noise: Linux < 5.9 doesn't respect ignore
	// masks on files when the parent directory is the object being watched:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	ignoreFileList := []string{
		"passwd",
		"log.json",
		"runtime",
	}
	for _, ignoreFile := range ignoreFileList {
		ignoreFilePath := filepath.Join(bundleDir, ignoreFile)
		// No need to os.Stat() before: this is best-effort and we ignore the
		// errors. Not all files are guaranteed to exist depending on the
		// container runtime.
		err := n.pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, ignoreFilePath)
		if err != nil {
			log.Debugf("fanotify: marking %s: %v", ignoreFilePath, err)
		} else {
			removeMarks = append(removeMarks, func() {
				_ = n.pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, ignoreFilePath)
			})
		}
	}

	// cri-o appends userdata to bundleDir,
	// so we trim it here to get the correct containerID
	containerID := filepath.Base(filepath.Clean(strings.TrimSuffix(bundleDir, "userdata")))

	n.pendingMu.Lock()
	defer n.pendingMu.Unlock()

	// Delete old entries
	now := time.Now()
	n.pendingContainers[pidFile] = &pendingContainer{
		id:             containerID,
		bundleDir:      bundleDir,
		configJSONPath: configJSONPath,
		pidFile:        pidFile,
		pidFileDir:     pidFileDir,
		timestamp:      now,
		removeMarks:    removeMarks,
	}

	return nil
}

func (n *ContainerNotifier) watchRuntimeBinary() {
	defer n.wg.Done()

	for {
		err := n.watchRuntimeIterate()
		if n.closed.Load() {
			return
		}
		if err != nil {
			log.Errorf("error watching runtime binary: %v\n", err)
			return
		}
	}
}

func (n *ContainerNotifier) watchPendingContainers() {
	defer n.wg.Done()

	for {
		err := n.watchPidFileIterate()
		if n.closed.Load() {
			return
		}
		if err != nil {
			log.Errorf("error watching pid file directories: %v\n", err)
			return
		}
	}
}

func (n *ContainerNotifier) checkTimeout() {
	defer n.wg.Done()

	ticker := time.NewTicker(containerCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			now := time.Now()

			n.futureMu.Lock()
			for id, fc := range n.futureContainers {
				if now.Sub(fc.timestamp) > containerPendingTimeout {
					delete(n.futureContainers, id)
				}
			}
			n.futureMu.Unlock()

			n.pendingMu.Lock()
			for id, pc := range n.pendingContainers {
				if now.Sub(pc.timestamp) > containerPendingTimeout {
					for _, remove := range pc.removeMarks {
						remove()
					}
					delete(n.pendingContainers, id)
				}
			}
			n.pendingMu.Unlock()
		}
	}
}

func (n *ContainerNotifier) parseConmonCmdline(cmdlineArr []string) {
	containerName := ""
	containerID := ""
	bundleDir := ""
	pidFile := ""

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

	if containerName == "" || containerID == "" || bundleDir == "" || pidFile == "" {
		return
	}

	n.futureMu.Lock()
	n.futureContainers[containerID] = &futureContainer{
		id:        containerID,
		pidFile:   pidFile,
		bundleDir: bundleDir,
		name:      containerName,
		timestamp: time.Now(),
	}
	n.futureMu.Unlock()
}

func (n *ContainerNotifier) parseOCIRuntime(comm string, cmdlineArr []string) {
	// Parse oci-runtime (runc/crun) command line
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
			bundleDir = filepath.Join(host.HostRoot, cmdlineArr[i])
			continue
		}
		if cmdlineArr[i] == "--pid-file" && i+1 < len(cmdlineArr) {
			i++
			pidFile = filepath.Join(host.HostRoot, cmdlineArr[i])
			continue
		}
	}

	if createFound && bundleDir != "" && pidFile != "" {
		err := n.monitorRuntimeInstance(bundleDir, pidFile)
		if err != nil {
			log.Errorf("error monitoring runtime instance: %v\n", err)
		}
	}
}

func (n *ContainerNotifier) watchRuntimeIterate() error {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use it here
	// because ResponseAllow would not be called.
	data, err := n.runtimeBinaryNotify.GetEvent()
	if err != nil {
		return err
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return nil
	}

	// Don't leak the fd received by GetEvent
	defer data.Close()

	if !data.MatchMask(unix.FAN_OPEN_EXEC_PERM) {
		// This should not happen: FAN_OPEN_EXEC_PERM is the only mask Marked
		log.Errorf("fanotify: unknown event on runtime: mask=%d pid=%d", data.Mask, data.Pid)
		return nil
	}

	// This unblocks the execution
	defer n.runtimeBinaryNotify.ResponseAllow(data)

	// Lookup entry in ebpf map ig_fa_records
	var record execruntimeRecord
	err = n.objs.IgFaRecords.LookupAndDelete(nil, &record)
	if err != nil {
		log.Errorf("fanotify: lookup record: %s", err)
		return nil
	}

	// Skip empty record
	// This can happen when the ebpf code didn't find the exec args
	if record.Pid == 0 {
		log.Debugf("fanotify: skip event with pid=0")
		return nil
	}
	if record.ArgsSize == 0 {
		log.Debugf("fanotify: skip event without args")
		return nil
	}

	callerComm := strings.TrimRight(string(record.CallerComm[:]), "\x00")

	cmdlineArr := []string{}
	calleeComm := ""
	for _, arg := range strings.Split(string(record.Args[0:record.ArgsSize]), "\x00") {
		if arg != "" {
			cmdlineArr = append(cmdlineArr, arg)
		}
	}
	if len(cmdlineArr) == 0 {
		log.Debugf("fanotify: cannot get cmdline for pid %d", record.Pid)
		return nil
	}
	if len(cmdlineArr) > 0 {
		calleeComm = filepath.Base(cmdlineArr[0])
	}

	log.Debugf("got event with pid=%d caller=%q callee=%q args=%v",
		record.Pid,
		callerComm, calleeComm,
		cmdlineArr)

	// runc is executing itself with unix.Exec(), so fanotify receives two
	// FAN_OPEN_EXEC_PERM events:
	//   1. from containerd-shim (or similar)
	//   2. from runc, by this re-execution.
	// This filter takes the first one.

	switch calleeComm {
	case "conmon":
		// Calling sequence: crio/podman -> conmon -> runc/crun
		n.parseConmonCmdline(cmdlineArr)
	case "runc", "crun":
		n.parseOCIRuntime(calleeComm, cmdlineArr)
	default:
		return nil
	}

	return nil
}

func (n *ContainerNotifier) Close() {
	n.closed.Store(true)
	close(n.done)
	if n.runtimeBinaryNotify != nil {
		n.runtimeBinaryNotify.File.Close()
	}
	if n.pidFileDirNotify != nil {
		n.pidFileDirNotify.File.Close()
	}
	n.wg.Wait()

	for _, l := range n.links {
		gadgets.CloseLink(l)
	}
	n.links = nil
	n.objs.Close()
}

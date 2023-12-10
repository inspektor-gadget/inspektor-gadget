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

type futureContainer struct {
	id        string
	name      string
	bundleDir string
	pidFile   string
}

type ContainerNotifier struct {
	runtimeBinaryNotify *fanotify.NotifyFD
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

	objs  execruntimeObjects
	links []link.Link

	// set to true when the notifier is closed is closed
	closed atomic.Bool
	// this channel is used in watchContainersTermination() to avoid having to wait for the
	// ticker to trigger before returning
	done chan bool

	wg sync.WaitGroup
}

// runtimePaths is the list of paths where the container runtime runc or crun
// could be installed. Depending on the Linux distribution, it could be in
// different locations.
//
// When this package is executed in a container, it prepends the
// HOST_ROOT env variable to the path.
var runtimePaths = []string{
	"/bin/runc",
	"/usr/bin/runc",
	"/usr/sbin/runc",
	"/usr/local/bin/runc",
	"/usr/local/sbin/runc",
	"/usr/lib/cri-o-runc/sbin/runc",
	"/run/torcx/unpack/docker/bin/runc",
	"/usr/bin/crun",
	"/usr/bin/conmon",
}

// initFanotify initializes the fanotify API with the flags we need
func initFanotify() (*fanotify.NotifyFD, error) {
	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS | unix.FAN_NONBLOCK)
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
		callback:         callback,
		containers:       make(map[string]*watchedContainer),
		futureContainers: make(map[string]*futureContainer),
		done:             make(chan bool),
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

		if _, err := os.Stat(runtimePath); errors.Is(err, os.ErrNotExist) {
			return err
		}

		if err := runtimeBinaryNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, runtimePath); err != nil {
			return fmt.Errorf("fanotify marking of %s: %w", runtimePath, err)
		}
		runtimeFound = true
	} else {
		for _, r := range runtimePaths {
			runtimePath := filepath.Join(host.HostRoot, r)

			log.Debugf("container-hook: trying runtime at %s", runtimePath)

			if _, err := os.Stat(runtimePath); errors.Is(err, os.ErrNotExist) {
				log.Debugf("container-hook: runc at %s not found", runtimePath)
				continue
			}

			if err := runtimeBinaryNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, runtimePath); err != nil {
				log.Warnf("container-hook: failed to fanotify mark: %s", err)
				continue
			}
			runtimeFound = true
		}
	}

	if !runtimeFound {
		runtimeBinaryNotify.File.Close()
		return fmt.Errorf("no container runtime can be monitored with fanotify. The following paths were tested: %s. You can use the RUNTIME_PATH env variable to specify a custom path. If you are successful doing so, please open a PR to add your custom path to runtimePaths", strings.Join(runtimePaths, ","))
	}

	n.wg.Add(2)
	go n.watchContainersTermination()
	go n.watchRuntimeBinary()

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

func (n *ContainerNotifier) watchPidFileIterate(
	pidFileDirNotify *fanotify.NotifyFD,
	bundleDir string,
	configJSONPath string,
	pidFile string,
	pidFileDir string,
) (bool, error) {
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

	bundleConfigJSON, err := os.ReadFile(configJSONPath)
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
		log.Errorf("container %s with pid %d terminated before we could watch it: %s", containerID, containerPID, err)
		return true, nil
	}

	if containerPID > math.MaxUint32 {
		log.Errorf("Container PID (%d) exceeds math.MaxUint32 (%d)", containerPID, math.MaxUint32)
		return true, nil
	}

	var containerName string
	n.futureMu.Lock()
	fc, ok := n.futureContainers[containerID]
	if ok {
		containerName = fc.name
	}
	delete(n.futureContainers, containerID)
	n.futureMu.Unlock()

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

func (n *ContainerNotifier) monitorRuntimeInstance(bundleDir string, pidFile string) error {
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
	if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
		// podman might install config.json in the userdata directory
		configJSONPath = filepath.Join(bundleDir, "userdata", "config.json")
		if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
			pidFileDirNotify.File.Close()
			return fmt.Errorf("config not found at %s", configJSONPath)
		}
	}
	err = pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJSONPath)
	if err != nil {
		pidFileDirNotify.File.Close()
		return fmt.Errorf("marking %s: %w", configJSONPath, err)
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
			stop, err := n.watchPidFileIterate(pidFileDirNotify, bundleDir, configJSONPath, pidFile, pidFileDir)
			if n.closed.Load() {
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

func (n *ContainerNotifier) watchRuntimeBinary() {
	defer n.wg.Done()

	for {
		stop, err := n.watchRuntimeIterate()
		if n.closed.Load() {
			n.runtimeBinaryNotify.File.Close()
			return
		}
		if err != nil {
			log.Errorf("error watching runtime binary: %v\n", err)
		}
		if stop {
			n.runtimeBinaryNotify.File.Close()
			return
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

func (n *ContainerNotifier) watchRuntimeIterate() (bool, error) {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use it here
	// because ResponseAllow would not be called.
	data, err := n.runtimeBinaryNotify.GetEvent()
	if err != nil {
		return true, err
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
	defer n.runtimeBinaryNotify.ResponseAllow(data)

	// Lookup entry in ebpf map ig_fa_records
	var record execruntimeRecord
	err = n.objs.IgFaRecords.LookupAndDelete(nil, &record)
	if err != nil {
		return false, fmt.Errorf("lookup record: %w", err)
	}

	// Skip empty record
	// This can happen when the ebpf code didn't find the exec args
	if record.Pid == 0 {
		log.Debugf("skip event with pid=0")
		return false, nil
	}
	if record.ArgsSize == 0 {
		log.Debugf("skip event without args")
		return false, nil
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
		log.Debugf("cannot get cmdline for pid %d", record.Pid)
		return false, nil
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
		return false, nil
	}

	return false, nil
}

func (n *ContainerNotifier) Close() {
	n.closed.Store(true)
	close(n.done)
	if n.runtimeBinaryNotify != nil {
		n.runtimeBinaryNotify.File.Close()
	}
	n.wg.Wait()

	for _, l := range n.links {
		gadgets.CloseLink(l)
	}
	n.links = nil
	n.objs.Close()
}

// Copyright 2024 The Inspektor Gadget authors
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

// Package uprobetracer handles how uprobe/uretprobe programs are attached
// to containers. It has two running modes: `pending` mode and `running` mode.
//
// Before `AttachProg` is called, uprobetracer runs in `pending` mode, only
// maintaining the container PIDs ready to attach to.
//
// When `AttachProg` is called, uprobetracer enters the `running` mode and
// attaches to all pending containers. After that, it will never get back to
// the `pending` mode.
//
// In `running` mode, uprobetracer holds fd(s) of the executables, so we can
// use `/proc/self/fd/$fd` for attaching, it is used to avoid fd-reusing.
//
// Uprobetracer doesn't maintain ebpf.collection or perf-ring buffer by itself,
// those are hold by the parent tracer.
//
// All interfaces should hold locks, while inner functions do not.
package uprobetracer

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type ProgType uint32

const (
	ProgUprobe ProgType = iota
	ProgUretprobe
)

type inodeUUID struct {
	token uint64
}

func getInodeUUID(file *os.File) (inodeUUID, error) {
	// TODO: use `kfilefields` to get a unique token for each inode,
	// here we just use `fd` as token, making each file has a distinct token.
	return inodeUUID{uint64(file.Fd())}, nil
}

// inodeKeeper holds a file object, with the counter representing its
// reference count. The link is not nil only when the file is attached.
type inodeKeeper struct {
	counter int
	file    *os.File
	link    link.Link
}

func (t *inodeKeeper) close() {
	if t.link != nil {
		t.link.Close()
	}
	t.file.Close()
}

type Tracer[Event any] struct {
	progName       string
	progType       ProgType
	attachFilePath string
	attachSymbol   string
	prog           *ebpf.Program

	// keeps the inodes for each attached container
	// when users write library names in ebpf section names, it's possible to
	// find multiple libraries of different archs within the same container,
	// making this a one-to-many mapping
	containerPid2Inodes map[uint32][]inodeUUID
	// keeps the fd and refCount for each inodeUUID
	inodeRefCount map[inodeUUID]*inodeKeeper
	// used as a set, keeps PIDs of the pending containers
	pendingContainerPids map[uint32]bool

	logger logger.Logger

	closed bool
	mu     sync.Mutex
}

func NewTracer[Event any](logger logger.Logger) (*Tracer[Event], error) {
	t := &Tracer[Event]{
		containerPid2Inodes:  make(map[uint32][]inodeUUID),
		inodeRefCount:        make(map[inodeUUID]*inodeKeeper),
		pendingContainerPids: make(map[uint32]bool),
		logger:               logger,
		closed:               false,
	}
	return t, nil
}

// AttachProg loads the ebpf program, and try attaching if there are pending containers
func (t *Tracer[Event]) AttachProg(progName string, progType ProgType, attachTo string, prog *ebpf.Program) error {
	if progType != ProgUprobe && progType != ProgUretprobe {
		return fmt.Errorf("unsupported uprobe prog type: %q", progType)
	}

	if prog == nil {
		return errors.New("prog does not exist")
	}
	if t.prog != nil {
		return errors.New("loading uprobe program twice")
	}

	parts := strings.Split(attachTo, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid section name %q", attachTo)
	}
	if !filepath.IsAbs(parts[0]) && strings.Contains(parts[0], "/") {
		return fmt.Errorf("section name must be either an absolute path or a library name: %q", parts[0])
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("uprobetracer has been closed")
	}

	t.progName = progName
	t.progType = progType
	t.attachFilePath = parts[0]
	t.attachSymbol = parts[1]
	t.prog = prog

	// attach to pending containers, then release the pending list
	for pid := range t.pendingContainerPids {
		t.attach(pid)
	}
	t.pendingContainerPids = nil

	return nil
}

func (t *Tracer[Event]) searchForLibrary(containerPid uint32) ([]string, error) {
	var targetPaths []string
	var securedTargetPaths []string

	filePath := t.attachFilePath
	if !filepath.IsAbs(filePath) {
		containerLdCachePath, err := securejoin.SecureJoin(filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root"), "etc/ld.so.cache")
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", filePath, err)
		}
		ldCachePaths, err := parseLdCache(containerLdCachePath, filePath)
		if err != nil {
			return nil, fmt.Errorf("parsing ld cache: %w", err)
		}
		targetPaths = ldCachePaths
	} else {
		targetPaths = append(targetPaths, filePath)
	}
	for _, targetPath := range targetPaths {
		securedTargetPath, err := securejoin.SecureJoin(filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root"), targetPath)
		if err != nil {
			t.logger.Debugf("path %q in ld cache is not available: %q", filePath, err.Error())
			continue
		}
		securedTargetPaths = append(securedTargetPaths, securedTargetPath)
	}
	return securedTargetPaths, nil
}

// attach uprobe program to the inode of the file passed in parameter
func (t *Tracer[Event]) attachUprobe(file *os.File) (link.Link, error) {
	attachPath := path.Join(host.HostProcFs, "self/fd/", fmt.Sprint(file.Fd()))
	ex, err := link.OpenExecutable(attachPath)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", attachPath, err)
	}
	switch t.progType {
	case ProgUprobe:
		return ex.Uprobe(t.attachSymbol, t.prog, nil)
	case ProgUretprobe:
		return ex.Uretprobe(t.attachSymbol, t.prog, nil)
	default:
		return nil, fmt.Errorf("attaching to inode: unsupported prog type: %q", t.progType)
	}
}

// try attaching to a container, will update `containerPid2Inodes`
func (t *Tracer[Event]) attach(containerPid uint32) {
	var attachedUUIDs []inodeUUID
	attachFilePaths, err := t.searchForLibrary(containerPid)
	if err != nil {
		t.logger.Debugf("attaching to container %d: %q", containerPid, err.Error())
	}

	if len(attachFilePaths) == 0 {
		t.logger.Debugf("cannot find file to attach in container %d for symbol %q", containerPid, t.attachSymbol)
	}

	for _, filePath := range attachFilePaths {
		file, err := os.OpenFile(filePath, unix.O_PATH, 0)
		if err != nil {
			t.logger.Debugf("opening file '%q' for uprobe: %q", filePath, err.Error())
			continue
		}
		fileUUID, err := getInodeUUID(file)
		if err != nil {
			t.logger.Debugf("getting inode info for '%q': %q", filePath, err.Error())
			file.Close()
			continue
		}

		t.logger.Debugf("attaching uprobe %q to container %d: %q", t.attachSymbol, containerPid, filePath)
		attachedUUIDs = append(attachedUUIDs, fileUUID)

		inode, exists := t.inodeRefCount[fileUUID]
		if !exists {
			progLink, _ := t.attachUprobe(file)
			t.inodeRefCount[fileUUID] = &inodeKeeper{1, file, progLink}
		} else {
			inode.counter++
			file.Close()
		}
	}

	t.containerPid2Inodes[containerPid] = attachedUUIDs
}

// AttachContainer will attach now if the prog is ready, otherwise it will add container into the pending list
func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("uprobetracer has been closed")
	}

	if t.prog == nil {
		_, exist := t.pendingContainerPids[container.Pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", container.Pid)
		}
		t.pendingContainerPids[container.Pid] = true
	} else {
		_, exist := t.containerPid2Inodes[container.Pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", container.Pid)
		}
		t.attach(container.Pid)
	}
	return nil
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	if t.prog == nil {
		// remove from pending list
		_, exist := t.pendingContainerPids[container.Pid]
		if !exist {
			return errors.New("container has not been attached")
		}
		delete(t.pendingContainerPids, container.Pid)
	} else {
		// detach from container if attached
		attachedUUIDs, exist := t.containerPid2Inodes[container.Pid]
		if !exist {
			return errors.New("container has not been attached")
		}
		delete(t.containerPid2Inodes, container.Pid)

		for _, attachedUUID := range attachedUUIDs {
			keeper, exist := t.inodeRefCount[attachedUUID]
			if !exist {
				return errors.New("internal error: finding inodeKeeper with inodeUUID")
			}
			keeper.counter--
			if keeper.counter == 0 {
				keeper.close()
				delete(t.inodeRefCount, attachedUUID)
			}
		}
	}

	return nil
}

func (t *Tracer[Event]) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}

	for _, keeper := range t.inodeRefCount {
		keeper.close()
	}

	t.containerPid2Inodes = nil
	t.inodeRefCount = nil
	t.closed = true
}

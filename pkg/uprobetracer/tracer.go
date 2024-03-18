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

// Package uprobetracer handles how uprobe/uretprobe/USDT programs are attached
// to containers. It has two running modes: `pending` mode and `running` mode.
//
// Before `AttachProg` is called, uprobetracer runs in `pending` mode, only
// maintaining the container PIDs ready to attach to.
//
// When `AttachProg` is called, uprobetracer enters the `running` mode and
// attaches to all pending containers. After that, it will never get back to
// the `pending` mode.
//
// Uprobetracer doesn't maintain ebpf.collection or perf-ring buffer by itself,
// those are hold by the parent tracer.
//
// All interfaces should hold locks, while inner functions do not.
package uprobetracer

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cyphar/filepath-securejoin"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type ProgType uint32

const (
	ProgUprobe    ProgType = 1
	ProgUretprobe ProgType = 2
)

type Tracer[Event any] struct {
	progName       string
	progType       ProgType
	attachFilePath string
	attachSymbol   string
	prog           *ebpf.Program

	// keeps the ebpf links for each attached container
	// when users write library names in ebpf section names, it's possible to
	// find multiple libraries of different archs within the same container,
	// making this a one-to-many mapping
	containerPid2Links map[uint32][]link.Link
	// used as a set, keeps PIDs of the pending containers
	pendingContainerPids map[uint32]bool

	closed bool

	mu sync.Mutex
}

func NewTracer[Event any]() (_ *Tracer[Event], err error) {
	t := &Tracer[Event]{
		containerPid2Links:   make(map[uint32][]link.Link),
		pendingContainerPids: make(map[uint32]bool),
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
		return fmt.Errorf("prog does not exist")
	}
	if t.prog != nil {
		return fmt.Errorf("loading uprobe program twice")
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
		return fmt.Errorf("uprobetracer has been closed")
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

func searchForLibrary(containerPid uint32, filePath string) []string {
	var libraryPaths []string
	var securedLibraryPaths []string

	if !filepath.IsAbs(filePath) {
		containerLdCachePath, err := securejoin.SecureJoin(filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root"), "etc/ld.so.cache")
		if err == nil {
			ldCachePaths := parseLdCache(containerLdCachePath, filePath)
			if ldCachePaths != nil {
				libraryPaths = ldCachePaths
			}
		}
	} else {
		libraryPaths = append(libraryPaths, filePath)
	}
	for _, libraryPath := range libraryPaths {
		securedLibraryPath, err := securejoin.SecureJoin(filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root"), libraryPath)
		if err == nil {
			securedLibraryPaths = append(securedLibraryPaths, securedLibraryPath)
		}
	}
	return securedLibraryPaths
}

// attach ebpf program to a self-hosted inode
func (t *Tracer[Event]) attachEbpf(attachPath string, containerPid uint32) (link.Link, error) {
	ex, err := link.OpenExecutable(attachPath)
	if err != nil {
		return nil, fmt.Errorf("opening executable %q", attachPath)
	}

	option := &link.UprobeOptions{
		PID: int(containerPid),
	}

	switch t.progType {
	case ProgUprobe:
		return ex.Uprobe(t.attachSymbol, t.prog, option)
	case ProgUretprobe:
		return ex.Uretprobe(t.attachSymbol, t.prog, option)
	default:
		return nil, fmt.Errorf("internal error: unsupported prog type: %q", t.progType)
	}
}

// try attaching to a container, will update `containerPid2Links`
func (t *Tracer[Event]) attach(containerPid uint32) {
	var attachedLinks []link.Link
	attachFilePaths := searchForLibrary(containerPid, t.attachFilePath)

	for _, attachPath := range attachFilePaths {
		l, err := t.attachEbpf(attachPath, containerPid)
		if err == nil {
			attachedLinks = append(attachedLinks, l)
		}
	}

	t.containerPid2Links[containerPid] = attachedLinks
}

// AttachContainer will attach now if the prog is ready, otherwise it will add container into the pending list
func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return fmt.Errorf("uprobetracer has been closed")
	}

	if t.prog == nil {
		_, exist := t.pendingContainerPids[container.Pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", container.Pid)
		}
		t.pendingContainerPids[container.Pid] = true
	} else {
		_, exist := t.containerPid2Links[container.Pid]
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
			return fmt.Errorf("container has not been attached")
		}
		delete(t.pendingContainerPids, container.Pid)
	} else {
		// detach from container if attached
		attachedLinks, exist := t.containerPid2Links[container.Pid]
		if !exist {
			return fmt.Errorf("container has not been attached")
		}
		delete(t.containerPid2Links, container.Pid)

		for _, l := range attachedLinks {
			l.Close()
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

	for _, links := range t.containerPid2Links {
		for _, l := range links {
			l.Close()
		}
	}

	t.containerPid2Links = nil
	t.closed = true
}

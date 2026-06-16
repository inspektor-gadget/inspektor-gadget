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

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kfilefields"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/secureopen"
)

type ProgType uint32

const (
	ProgUprobe ProgType = iota
	ProgUretprobe
	ProgUSDT
)

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
	containerPid2Inodes map[uint32][]uint64
	// keeps the fd and refCount for each realInodePtr
	//
	// we are using `realInodePtr` (the address of real inode in kernel) to identify a file
	// instead of just the inode number.
	// Since overlayFS overwrites the FsID of files and provides its own inode implementation,
	// we cannot uniquely identify a file on disk using `<FsID, inode>` pairs.
	//
	// Meanwhile, uprobe is using kernel function `d_real_inode` to get the underlying inode,
	// and attaching onto it. That means if we are attaching to one container, other containers
	// sharing the same image will also be attached. If we are attaching to multiple containers,
	// the underlying inode might be attached multiple times, leading to duplicate records.
	//
	// To deduplicate, we need to identify the underlying inode hidden by overlayFS,
	// and use it as a unique identifier. For each realInodePtr, we only attach to it once.
	inodeRefCount map[uint64]*inodeKeeper
	// used as a set, keeps PIDs of the pending containers
	pendingContainerPids map[uint32]bool

	// keeps the OCI runtime config (verbatim config.json) per attached/pending
	// container PID, recorded at AttachContainer. Used to resolve a container's
	// intended executable (process.args[0]) when a targeted library is statically
	// linked into the binary rather than present as a shared object — see
	// searchForLibrary. Kept here so the pending-attach path (which only has PIDs)
	// can still resolve the executable once the program loads.
	containerPid2OciConfig map[uint32]string

	logger logger.Logger

	closed bool
	mu     sync.Mutex
}

func NewTracer[Event any](logger logger.Logger) (*Tracer[Event], error) {
	t := &Tracer[Event]{
		containerPid2Inodes:    make(map[uint32][]uint64),
		inodeRefCount:          make(map[uint64]*inodeKeeper),
		pendingContainerPids:   make(map[uint32]bool),
		containerPid2OciConfig: make(map[uint32]string),
		logger:                 logger,
		closed:                 false,
	}
	return t, nil
}

// AttachProg loads the ebpf program, and try attaching if there are pending containers
func (t *Tracer[Event]) AttachProg(progName string, progType ProgType, attachTo string, prog *ebpf.Program) error {
	if progType != ProgUprobe && progType != ProgUretprobe && progType != ProgUSDT {
		return fmt.Errorf("unsupported uprobe prog type: %q", progType)
	}

	if prog == nil {
		return errors.New("prog does not exist")
	}
	if t.prog != nil {
		return errors.New("loading uprobe program twice")
	}

	parts := strings.SplitN(attachTo, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid section name %q", attachTo)
	}
	if !filepath.IsAbs(parts[0]) && strings.Contains(parts[0], "/") {
		return fmt.Errorf("section name must be either an absolute path or a library name: %q", parts[0])
	}
	if progType == ProgUSDT && len(strings.Split(parts[1], ":")) != 2 {
		return fmt.Errorf("invalid USDT section name: %q", attachTo)
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
	filePath := t.attachFilePath
	if filepath.IsAbs(filePath) {
		return []string{filePath}, nil
	}

	ldCachePath := "/etc/ld.so.cache"
	ldCachePaths, err := parseLdCache(containerPid, ldCachePath, filePath)
	if err != nil {
		return nil, fmt.Errorf("parsing ld cache: %w", err)
	}
	if len(ldCachePaths) > 0 {
		return ldCachePaths, nil
	}

	// The requested library is not a shared object in this container's ld cache.
	// This is the common case for statically-linked runtimes that embed the
	// library into their main executable (Node.js, and Go/Rust binaries that
	// statically link OpenSSL/BoringSSL), where a `libssl`-targeted uprobe gadget
	// would otherwise find nothing to attach to. Fall back to the container's
	// intended executable: the symbol may be defined there.
	//
	// The executable is resolved from the OCI runtime config (process.args[0]),
	// NOT from /proc/<pid>/exe: at container-create time (when AttachContainer
	// fires) the PID still points at the runtime shim, because runc execve's into
	// the entrypoint in-place slightly later and a uprobe binds an inode without
	// following execve. The OCI-spec value is the in-rootfs path of the settled
	// binary, opened via the same OpenInContainer mechanism as a shared library —
	// so ReadRealInodeFromFd dedup and per-image attach-once are preserved, and
	// attachUprobe skips (logged) any executable that does not export the symbol.
	exePath, ok := t.containerExecutableFromOCI(containerPid)
	if !ok {
		return nil, nil
	}
	return []string{exePath}, nil
}

// containerExecutableFromOCI resolves a container's intended executable to its
// in-container absolute path from the OCI config recorded at AttachContainer
// (process.args[0]). First cut: only absolute argv[0] is supported (covers
// Node.js and most images, whose runtime resolves the image Entrypoint/Cmd to an
// absolute path); a relative argv[0] resolved against PATH is a follow-up.
func (t *Tracer[Event]) containerExecutableFromOCI(containerPid uint32) (string, bool) {
	ociConfig, ok := t.containerPid2OciConfig[containerPid]
	if !ok || ociConfig == "" {
		return "", false
	}
	args, err := containercollection.OCIConfigGetProcessArgs(ociConfig)
	if err != nil || len(args) == 0 {
		t.logger.Debugf("uprobetracer: container %d: cannot read process args from OCI config: %v", containerPid, err)
		return "", false
	}
	exe := args[0]
	if !filepath.IsAbs(exe) {
		t.logger.Debugf("uprobetracer: container %d: entrypoint %q is not absolute; PATH resolution not yet supported", containerPid, exe)
		return "", false
	}
	t.logger.Debugf("uprobetracer: %q not in ld cache for container %d; attaching to executable %q from OCI spec", t.attachFilePath, containerPid, exe)
	return exe, true
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
	case ProgUSDT:
		attachInfo, err := getUsdtInfo(attachPath, t.attachSymbol)
		if err != nil {
			return nil, fmt.Errorf("reading USDT metadata: %w", err)
		}
		return ex.Uprobe(t.attachSymbol, t.prog,
			&link.UprobeOptions{
				Address:      attachInfo.attachAddress,
				RefCtrOffset: attachInfo.semaphoreAddress,
			})
	default:
		return nil, fmt.Errorf("attaching to inode: unsupported prog type: %q", t.progType)
	}
}

// try attaching to a container, will update `containerPid2Inodes`
func (t *Tracer[Event]) attach(containerPid uint32) {
	var attachedRealInodes []uint64
	unsecuredAttachFilePaths, err := t.searchForLibrary(containerPid)
	if err != nil {
		t.logger.Debugf("attaching to container %d: %s", containerPid, err.Error())
	}

	if len(unsecuredAttachFilePaths) == 0 {
		t.logger.Debugf("cannot find file to attach in container %d for symbol %q", containerPid, t.attachSymbol)
	}

	for _, filePath := range unsecuredAttachFilePaths {
		// Thankfully, OpenInContainer returns a fd opened without `O_PATH`.
		// This is necessary because `ReadRealInodeFromFd` needs the
		// `private_data` field in kernel "struct file", to access the
		// underlying inode through overlayFS. Using `O_PATH` flag will cause
		// the `private_data` field to be zero.
		file, err := secureopen.OpenInContainer(containerPid, filePath)
		if err != nil {
			t.logger.Debugf("opening file '%q' for uprobe: %s", filePath, err.Error())
			continue
		}
		realInodePtr, err := kfilefields.ReadRealInodeFromFd(int(file.Fd()))
		if err != nil {
			t.logger.Debugf("getting inode info for '%q': %s", filePath, err.Error())
			file.Close()
			continue
		}

		t.logger.Debugf("attaching uprobe %q to container %d: %q", t.progName, containerPid, filePath)
		attachedRealInodes = append(attachedRealInodes, realInodePtr)

		inode, exists := t.inodeRefCount[realInodePtr]
		if !exists {
			progLink, err := t.attachUprobe(file)
			if err != nil {
				t.logger.Debugf("failed to attach uprobe %q: %s", t.progName, err.Error())
			}
			t.inodeRefCount[realInodePtr] = &inodeKeeper{1, file, progLink}
		} else {
			inode.counter++
			file.Close()
		}
	}

	t.containerPid2Inodes[containerPid] = attachedRealInodes
}

// AttachContainer will attach now if the prog is ready, otherwise it will add container into the pending list
func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("uprobetracer has been closed")
	}

	pid := container.ContainerPid()
	// Record the OCI config so the (possibly deferred) attach can resolve a
	// statically-linked symbol to the container's executable via the OCI spec.
	t.containerPid2OciConfig[pid] = container.OciConfig
	if t.prog == nil {
		_, exist := t.pendingContainerPids[pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", pid)
		}
		t.pendingContainerPids[pid] = true
	} else {
		_, exist := t.containerPid2Inodes[pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", pid)
		}
		t.attach(pid)
	}
	return nil
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	pid := container.ContainerPid()
	delete(t.containerPid2OciConfig, pid)
	if t.prog == nil {
		// remove from pending list
		_, exist := t.pendingContainerPids[pid]
		if !exist {
			return errors.New("container has not been attached")
		}
		delete(t.pendingContainerPids, pid)
	} else {
		// detach from container if attached
		attachedRealInodes, exist := t.containerPid2Inodes[pid]
		if !exist {
			return errors.New("container has not been attached")
		}
		delete(t.containerPid2Inodes, pid)

		for _, realInodePtr := range attachedRealInodes {
			keeper, exist := t.inodeRefCount[realInodePtr]
			if !exist {
				return errors.New("internal error: finding inodeKeeper with realInodePtr")
			}
			keeper.counter--
			if keeper.counter == 0 {
				keeper.close()
				delete(t.inodeRefCount, realInodePtr)
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

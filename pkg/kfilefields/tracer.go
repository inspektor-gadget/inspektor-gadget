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

package kfilefields

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types filefields ./bpf/filefields.bpf.c -- -I./bpf/

type FdType int

const (
	FdTypeSocket FdType = iota
	FdTypeEbpfProgram
)

var supportedFdTypesForFOp = map[FdType]struct{}{
	FdTypeSocket:      {},
	FdTypeEbpfProgram: {},
}

func (fd FdType) String() string {
	switch fd {
	case FdTypeSocket:
		return "socket"
	case FdTypeEbpfProgram:
		return "ebpf_program"
	default:
		return fmt.Sprintf("unknown(%d)", fd)
	}
}

type fileFields struct {
	PrivateData uint64
	FOp         uint64
	RealInode   uint64
}

type Tracer struct {
	objs      filefieldsObjects
	links     []link.Link
	sock      [2]int
	installed bool
}

func creatAndInstallTracer() (*Tracer, error) {
	t := &Tracer{}

	if err := t.install(); err != nil {
		t.close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
}

func (t *Tracer) close() {
	for _, l := range t.links {
		gadgets.CloseLink(l)
	}
	for i := 0; i < len(t.sock); i++ {
		if t.sock[i] != -1 {
			unix.Close(t.sock[i])
		}
	}
	t.objs.Close()
}

func (t *Tracer) install() error {
	// Create a socket pair
	var err error
	t.sock, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("creating socket pair: %w", err)
	}

	// Find the inode of the socket
	fdFileInfo, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", t.sock[0]))
	if err != nil {
		return fmt.Errorf("reading file info from sock fd %d: %w", t.sock[0], err)
	}
	fdStat, ok := fdFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("not a syscall.Stat_t")
	}

	// Load ebpf program configured with the socket inode
	spec, err := loadFilefields()
	if err != nil {
		return fmt.Errorf("load ebpf program to read file fields: %w", err)
	}
	filefieldSpec := &filefieldsSpecs{}
	if err := spec.Assign(filefieldSpec); err != nil {
		return err
	}

	if err := filefieldSpec.SocketIno.Set(uint64(fdStat.Ino)); err != nil {
		return err
	}

	programs := []*ebpf.ProgramSpec{}
	for _, p := range spec.Programs {
		programs = append(programs, p)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(programs...),
		},
	}
	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("loading maps and programs: %w", err)
	}

	// Attach ebpf programs
	l, err := link.Kprobe("__scm_send", t.objs.IgScmSndE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe __scm_send: %w", err)
	}
	t.links = append(t.links, l)

	l, err = link.Kretprobe("fget_raw", t.objs.IgFgetX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe fget_raw: %w", err)
	}
	t.links = append(t.links, l)
	t.installed = true

	return nil
}

func (t *Tracer) getFdFromType(kind FdType) (int, error) {
	if !t.installed {
		return -1, errors.New("tracer not installed")
	}
	switch kind {
	case FdTypeSocket:
		return t.sock[0], nil
	case FdTypeEbpfProgram:
		return t.objs.IgFgetX.FD(), nil
	default:
		return -1, fmt.Errorf("unknown fd type %d", kind)
	}
}

func (t *Tracer) readStructFileFields(fd int) (*fileFields, error) {
	if !t.installed {
		return nil, errors.New("tracer not installed")
	}
	// Send the fd through the socket with SCM_RIGHTS.
	// This will trigger the __scm_send kprobe and fget_raw kretprobe
	buf := make([]byte, 1)
	err := unix.Sendmsg(t.sock[0], buf, unix.UnixRights(fd), nil, 0)
	if err != nil {
		return nil, fmt.Errorf("sending fd: %w", err)
	}

	var ff fileFields
	err = t.objs.IgFileFields.Lookup(uint32(0), &ff)
	if err != nil {
		return nil, fmt.Errorf("reading file fields: %w", err)
	}

	return &ff, nil
}

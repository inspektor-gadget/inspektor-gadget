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

// Package kfilefields provides functions to read kernel "struct file" fields against a file descriptor.
//
// This is done:
//   - without using bpf iterators in order to work on old kernels.
//   - without comparing pids from userspace and ebpf in order to work from
//     different pid namespaces.
package kfilefields

import (
	"fmt"
	"sync"
)

// The tracer is expensive to create: installing it loads a BPF collection
// (parsing the full kernel BTF, several MB) and attaches two kprobes. Doing that
// per call caused large allocation churn under high call rates — e.g. uprobe
// re-attach on exec calls ReadRealInodeFromFd once per attach, which under an
// exec/pod burst produced a multi-hundred-MB spike and OOMs. The tracer's BPF
// program is fd-agnostic (the fd is passed in per read), so a single
// process-wide instance serves every Read*. It is created lazily on first use
// and kept for the process lifetime.
//
// tracerMu also serializes reads: the tracer's socketpair and its single-slot
// result map are not safe for concurrent use.
var (
	tracerMu      sync.Mutex
	sharedTracer  *Tracer
	tracerErr     error
	tracerCreated bool
)

// sharedTracerLocked returns the lazily-created process-wide tracer. The caller
// must hold tracerMu.
func sharedTracerLocked() (*Tracer, error) {
	if !tracerCreated {
		sharedTracer, tracerErr = creatAndInstallTracer()
		tracerCreated = true
	}
	return sharedTracer, tracerErr
}

// ReadPrivateDataFromFd uses ebpf to read the private_data pointer from the
// kernel "struct file" associated with the given fd.
func ReadPrivateDataFromFd(fd int) (uint64, error) {
	tracerMu.Lock()
	defer tracerMu.Unlock()
	t, err := sharedTracerLocked()
	if err != nil {
		return 0, fmt.Errorf("creating and installing tracer: %w", err)
	}
	ff, err := t.readStructFileFields(fd)
	if err != nil {
		return 0, fmt.Errorf("reading file fields: %w", err)
	}
	return ff.PrivateData, nil
}

// ReadFOpForFdType uses ebpf to read the f_op pointer from the kernel "struct file"
// associated with the given fd type.
func ReadFOpForFdType(ft FdType) (uint64, error) {
	if _, ok := supportedFdTypesForFOp[ft]; !ok {
		return 0, fmt.Errorf("unsupported fd type %s", ft.String())
	}
	tracerMu.Lock()
	defer tracerMu.Unlock()
	t, err := sharedTracerLocked()
	if err != nil {
		return 0, fmt.Errorf("creating and installing tracer: %w", err)
	}
	fd, err := t.getFdFromType(ft)
	if err != nil {
		return 0, fmt.Errorf("getting fd from type %s: %w", ft.String(), err)
	}
	ff, err := t.readStructFileFields(fd)
	if err != nil {
		return 0, fmt.Errorf("reading file fields: %w", err)
	}
	return ff.FOp, nil
}

// ReadRealInodeFromFd uses ebpf to read the f_inode pointer from the
// kernel "struct file" associated with the given fd.
// Specifically, if fd belongs to overlayFS, it will return the underlying, real inode.
//
// This feature makes it possible to check if two fds come from the same
// underlying file, even if they come from two different overlay filesystems.
// This is useful for uprobes because they get attached to the underlying file.
func ReadRealInodeFromFd(fd int) (uint64, error) {
	tracerMu.Lock()
	defer tracerMu.Unlock()
	t, err := sharedTracerLocked()
	if err != nil {
		return 0, fmt.Errorf("creating and installing tracer: %w", err)
	}
	ff, err := t.readStructFileFields(fd)
	if err != nil {
		return 0, fmt.Errorf("reading file fields: %w", err)
	}
	return ff.RealInode, nil
}

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

import "fmt"

// ReadPrivateDataFromFd uses ebpf to read the private_data pointer from the
// kernel "struct file" associated with the given fd.
func ReadPrivateDataFromFd(fd int) (uint64, error) {
	t, err := creatAndInstallTracer()
	if err != nil {
		return 0, fmt.Errorf("creating and installing tracer: %w", err)
	}
	defer t.close()
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
	t, err := creatAndInstallTracer()
	if err != nil {
		return 0, fmt.Errorf("creating and installing tracer: %w", err)
	}
	defer t.close()
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

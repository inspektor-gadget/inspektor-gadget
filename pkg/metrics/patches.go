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

package metrics

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This is a patched version of their counterparts from cilium/ebpf; the upstream code doesn't allow reading bytes
// from maps but instead wants to deserialize itself. However, we need to deserialize with our own libraries and
// thus get the raw data from the map in a performant way.

const (
	BPF_MAP_LOOKUP_AND_DELETE_BATCH uintptr = 25
)

type Pointer struct {
	ptr unsafe.Pointer
}

type MapLookupBatchAttr struct {
	InBatch   Pointer
	OutBatch  Pointer
	Keys      Pointer
	Values    Pointer
	Count     uint32
	MapFd     uint32
	ElemFlags uint64
	Flags     uint64
}

func BPF(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	for {
		r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		runtime.KeepAlive(attr)

		var err error
		if errNo != 0 {
			err = errNo
		}

		return r1, err
	}
}

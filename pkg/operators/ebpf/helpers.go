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

package ebpfoperator

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type (
	btfTypeValidator func(btf.Type, string) error
	btfPopulateFunc  func(btf.Type, string) error
	prefixFunc       func(string) (string, bool)
	populateEntry    struct {
		prefixFunc   prefixFunc
		validator    btfTypeValidator
		populateFunc btfPopulateFunc
	}
)

func hasPrefix(prefix string) prefixFunc {
	return func(s string) (string, bool) {
		return strings.TrimPrefix(s, prefix), strings.HasPrefix(s, prefix)
	}
}

var (
	onceRingbuf      sync.Once
	ringbufAvailable bool
)

func isRingbufAvailable() bool {
	onceRingbuf.Do(func() {
		ringbuf, err := ebpf.NewMap(&ebpf.MapSpec{
			Type:       ebpf.RingBuf,
			MaxEntries: uint32(os.Getpagesize()),
		})

		ringbuf.Close()

		ringbufAvailable = err == nil
	})

	return ringbufAvailable
}

func (i *ebpfInstance) validateGlobalConstVoidPtrVar(t btf.Type, varName string) error {
	btfVar, ok := t.(*btf.Var)
	if !ok {
		return errors.New("not of type btf.Var")
	}

	if btfVar.Linkage != btf.GlobalVar {
		return fmt.Errorf("%q is not a global variable", btfVar.Name)
	}

	btfPtr, ok := btfVar.Type.(*btf.Pointer)
	if !ok {
		return fmt.Errorf("%q is not a pointer", btfVar.Name)
	}

	btfConst, ok := btfPtr.Target.(*btf.Const)
	if !ok {
		return fmt.Errorf("%q is not const", btfVar.Name)
	}

	_, ok = btfConst.Type.(*btf.Void)
	if !ok {
		return fmt.Errorf("%q is not a const void pointer", btfVar.Name)
	}

	return nil
}

// uintFromBTF resolves the __uint macro, which is a pointer to a sized
// array, e.g. for int (*foo)[10], this function will return 10.
func uintFromBTF(typ btf.Type) (uint32, error) {
	ptr, ok := typ.(*btf.Pointer)
	if !ok {
		return 0, fmt.Errorf("not a pointer: %v", typ)
	}

	arr, ok := ptr.Target.(*btf.Array)
	if !ok {
		return 0, fmt.Errorf("not a pointer to array: %v", typ)
	}

	return arr.Nelems, nil
}

// same as above for __type
func typeFromBTF(typ btf.Type) (btf.Type, error) {
	vk, ok := typ.(*btf.Pointer)
	if !ok {
		return nil, fmt.Errorf("value type is not a pointer: %T", typ)
	}

	return vk.Target, nil
}

// same as above for __string
func stringFromBTF(typ btf.Type) (string, error) {
	vk, ok := typ.(*btf.Pointer)
	if !ok {
		return "", fmt.Errorf("value type is not a pointer: %T", typ)
	}

	typ = btf.UnderlyingType(vk.Target)
	fwd, ok := typ.(*btf.Fwd)
	if !ok {
		return "", fmt.Errorf("value type is not a forward declaration: %T", typ)
	}

	return fwd.Name, nil
}

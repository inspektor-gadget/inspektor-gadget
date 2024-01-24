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

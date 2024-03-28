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

package kallsyms

import (
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/kfilefields"
)

// symbolResolver is an interface to resolve kernel symbols.
type symbolResolver interface {
	resolve(symbol string) (uint64, error)
}

// kAllSymsResolver is a symbolResolver that resolves kernel symbols using a KAllSyms.
// It isn't safe for concurrent use.
type kAllSymsResolver struct {
	kAllSyms *KAllSyms
}

// newKAllSymsResolver returns a new kAllSymsResolver.
func newKAllSymsResolver() *kAllSymsResolver {
	return &kAllSymsResolver{}
}

// Resolve resolves a kernel symbol using the KAllSyms.
func (r *kAllSymsResolver) resolve(symbol string) (uint64, error) {
	if r.kAllSyms == nil {
		if err := r.init(); err != nil {
			return 0, fmt.Errorf("initializing kallsyms: %w", err)
		}
	}
	addr, ok := r.kAllSyms.symbolsMap[symbol]
	if !ok {
		return 0, fmt.Errorf("symbol %q was not found in kallsyms", symbol)
	}
	return addr, nil
}

func (r *kAllSymsResolver) init() error {
	kAllSyms, err := NewKAllSyms()
	if err != nil {
		return err
	}
	r.kAllSyms = kAllSyms
	return nil
}

// ebpfResolver is a symbolResolver that resolves kernel symbols using eBPF.
type ebpfResolver struct {
	symbolsBypass map[string]kfilefields.FdType
}

// newEbpfResolver returns a new ebpfResolver.
func newEbpfResolver() *ebpfResolver {
	// List of symbols that we're able to find in 'struct file *' using eBPF
	return &ebpfResolver{
		symbolsBypass: map[string]kfilefields.FdType{
			"bpf_prog_fops":   kfilefields.FdTypeEbpfProgram,
			"socket_file_ops": kfilefields.FdTypeSocket,
		},
	}
}

// Resolve resolves a kernel symbol using eBPF.
func (r *ebpfResolver) resolve(symbol string) (uint64, error) {
	fdT, ok := r.symbolsBypass[symbol]
	if !ok {
		return 0, os.ErrInvalid
	}

	fop, err := kfilefields.ReadFOpForFdType(fdT)
	if err != nil {
		return 0, err
	}
	return fop, nil
}

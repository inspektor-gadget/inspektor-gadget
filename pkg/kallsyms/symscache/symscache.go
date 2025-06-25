// Copyright 2025 The Inspektor Gadget authors
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

// Package symscache provides a way to register and populate the cilium/ebpf's
// kallsyms cache in an efficient way.
//
// The cost of loading many symbols at once is lower than loading few symbols
// multiple times for multiple ebpf collections.
//
// How to use this package:
// 1. Call RegisterSymbolsFromSpec from an init() function.
// 2. Call PopulateKallsymsCache just before loading your ebpf collection.
package symscache

import (
	"sync"

	"github.com/cilium/ebpf"
)

var (
	requestedSymbols []string

	populateKallsymsCache = sync.OnceFunc(func() {
		spec := &ebpf.CollectionSpec{
			Programs:  make(map[string]*ebpf.ProgramSpec),
			Maps:      make(map[string]*ebpf.MapSpec),
			Variables: make(map[string]*ebpf.VariableSpec),
		}
		for _, sym := range requestedSymbols {
			spec.Programs[sym] = &ebpf.ProgramSpec{
				Name:     sym,
				Type:     ebpf.Kprobe,
				AttachTo: sym,
			}
		}
		requestedSymbols = nil
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			// error is expected: "instructions cannot be empty"
			// cilium/ebpf will still load kallsyms in the cache
			return
		}
		coll.Close()
	})
)

// RegisterSymbolsFromSpec registers the symbols from the given
// ebpf.CollectionSpec. RegisterSymbolsFromSpec can be called from an init()
// function.
//
// Once all symbols are registered, the cache can be populated with
// PopulateKallsymsCache.
func RegisterSymbolsFromSpec(spec *ebpf.CollectionSpec) {
	for _, prog := range spec.Programs {
		if prog.AttachTo == "" {
			continue
		}
		if prog.Type != ebpf.Kprobe && prog.Type != ebpf.Tracing {
			continue
		}
		requestedSymbols = append(requestedSymbols, prog.AttachTo)
	}
}

// PopulateKallsymsCache populates cilium/ebpf's kallsyms cache with the
// symbols that were registered by RegisterSymbolsFromSpec.
//
// After the first call, subsequent calls will have no effect and have no
// performance impact.
func PopulateKallsymsCache() {
	populateKallsymsCache()
}

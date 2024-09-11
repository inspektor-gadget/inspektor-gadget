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

package uprobetracer

import (
	"debug/elf"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func getFunctions(filename string, lookups map[string]struct{}) (map[string]*Function, error) {
	elff, err := elf.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF: %w", err)
	}
	defer elff.Close()

	functions := make(map[string]*Function)

	// find symbols
	syms, err := elff.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("failed to get symbols: %w", err)
	}

	collectSymbols(elff, syms, functions, lookups)

	syms, err = elff.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("failed to get dynamic symbols: %w", err)
	}

	collectSymbols(elff, syms, functions, lookups)

	for name, function := range functions {
		data := make([]byte, function.Size)
		_, err := function.Prog.ReadAt(data, int64(function.Offset-function.Prog.Off))
		if err != nil {
			return nil, fmt.Errorf("failed to read data for function %q: %w", name, err)
		}

		function.Returns, err = findReturnOffsets(function.Offset, data)
		if err != nil {
			return nil, fmt.Errorf("failed to get return offsets for function %q: %w", name, err)
		}
	}

	return functions, nil
}

type Function struct {
	Offset  uint64
	Size    uint64
	Prog    *elf.Prog
	Returns []uint64
}

func collectSymbols(elff *elf.File, syms []elf.Symbol, target map[string]*Function, lookups map[string]struct{}) {
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		if _, ok := lookups[s.Name]; !ok {
			continue
		}
		address := s.Value

		log.Printf("found function %q", s.Name)
		var p *elf.Prog
		for _, prog := range elff.Progs {
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}
			// stackoverflow.com/a/40249502
			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				address = s.Value - prog.Vaddr + prog.Off
				p = prog
				break
			}
		}
		target[s.Name] = &Function{Offset: address, Size: s.Size, Prog: p}
	}
}

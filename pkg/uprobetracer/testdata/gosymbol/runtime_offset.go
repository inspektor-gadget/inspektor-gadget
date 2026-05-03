// Copyright 2026 The Inspektor Gadget authors
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

package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

func printTargetOffset() {
	offset, err := targetOffset()
	if err != nil {
		panic(err)
	}
	fmt.Println(offset)
}

func targetOffset() (uint64, error) {
	executable, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("getting executable path: %w", err)
	}

	runtimeBase, err := runtimeBaseAddress(executable)
	if err != nil {
		return 0, err
	}

	elfFile, err := elf.Open(executable)
	if err != nil {
		return 0, fmt.Errorf("opening ELF: %w", err)
	}
	defer elfFile.Close()

	elfBase, err := elfBaseAddress(elfFile)
	if err != nil {
		return 0, err
	}

	runtimeAddress := reflect.ValueOf(target).Pointer()
	virtualAddress := uint64(runtimeAddress) - runtimeBase + elfBase
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if virtualAddress < prog.Vaddr || virtualAddress-prog.Vaddr >= prog.Memsz {
			continue
		}
		return prog.Off + virtualAddress - prog.Vaddr, nil
	}
	return 0, fmt.Errorf("target address 0x%x is not in an executable LOAD segment", virtualAddress)
}

func runtimeBaseAddress(executable string) (uint64, error) {
	file, err := os.Open("/proc/self/maps")
	if err != nil {
		return 0, fmt.Errorf("opening process maps: %w", err)
	}
	defer file.Close()

	var base uint64
	found := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 || parts[5] != executable {
			continue
		}
		if parts[1] != "r--p" && parts[1] != "r-xp" {
			continue
		}
		start, _, ok := strings.Cut(parts[0], "-")
		if !ok {
			continue
		}
		address, err := strconv.ParseUint(start, 16, 64)
		if err != nil {
			continue
		}
		if !found || address < base {
			base = address
			found = true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading process maps: %w", err)
	}
	if !found {
		return 0, fmt.Errorf("executable mapping not found")
	}
	return base, nil
}

func elfBaseAddress(elfFile *elf.File) (uint64, error) {
	var base uint64
	found := false
	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if !found || prog.Vaddr < base {
			base = prog.Vaddr
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("ELF has no LOAD segments")
	}
	return base, nil
}

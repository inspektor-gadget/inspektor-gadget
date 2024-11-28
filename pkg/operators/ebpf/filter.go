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
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/net/bpf"
)

var demoProg = `24
40 0 0 12
21 0 8 34525
48 0 0 20
21 2 0 132
21 1 0 6
21 0 17 17
40 0 0 54
21 14 0 22
40 0 0 56
21 12 13 22
21 0 12 2048
48 0 0 23
21 2 0 132
21 1 0 6
21 0 8 17
40 0 0 20
69 6 0 8191
177 0 0 14
72 0 0 14
21 2 0 22
72 0 0 16
21 0 1 22
6 0 0 0
6 0 0 65535`

type BPFFilter struct {
	name       string
	mapName    string
	progMap    *ebpf.Map
	okProg     *ebpf.Program
	nokProg    *ebpf.Program
	filterProg *ebpf.Program
}

func (i *ebpfInstance) prepareBPFFilter(t btf.Type, varName string) error {
	i.logger.Debugf("preparing bpf filter %q", varName)

	info := strings.Split(varName, typeSplitter)
	if len(info) != 2 {
		return fmt.Errorf("invalid name for gadget_mapiter type: %q", varName)
	}

	name := info[0]
	mapName := info[1]

	i.logger.Debugf("bpf filter %s / %s", name, mapName)

	progArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		return err
	}

	xp, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R2, progArray.FD()), // Load map FD into R2
			asm.Mov.Imm(asm.R3, 1),                 // Set key (index) in R3
			asm.FnTailCall.Call(),
			asm.Mov.Imm(asm.R0, 0), // Default return value if tail call fails
			asm.Return(),
		},
		License: "GPL",
	})
	progArray.Put(uint32(1), xp.FD())

	filter := &BPFFilter{
		name:       name,
		mapName:    mapName,
		progMap:    progArray,
		filterProg: xp,
	}

	i.bpfFilters[name] = filter
	// // Get types
	// iterMap, ok := i.collectionSpec.Maps[mapName]

	return nil
}

func getDemoProg() ([]bpf.Instruction, error) {
	// Read lines
	lines := strings.Split(strings.Replace(demoProg, "\r", "", -1), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("unexpected output from tcpdump")
	}
	count, err := strconv.Atoi(lines[0])
	if err != nil {
		return nil, fmt.Errorf("expected first line from tcpdump to be count of instructions")
	}

	xInsns := make([]bpf.Instruction, 0, count)
	for _, line := range lines[1:] {
		parts := strings.Split(line, " ")
		if len(parts) != 4 {
			continue // skip empty lines
		}
		op, err := strconv.ParseInt(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid op %q in instruction: %q", parts[0], line)
		}
		jt, err := strconv.ParseInt(parts[0], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid jt %q in instruction: %q", parts[1], line)
		}
		jf, err := strconv.ParseInt(parts[0], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid jf %q in instruction: %q", parts[2], line)
		}
		k, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid k %q in instruction: %q", parts[3], line)
		}
		xInsns = append(xInsns, bpf.RawInstruction{
			Op: uint16(op),
			Jt: uint8(jt),
			Jf: uint8(jf),
			K:  uint32(k),
		}.Disassemble())
	}
	return xInsns, nil
}

// alu operation to eBPF
var aluToEBPF = map[bpf.ALUOp]asm.ALUOp{
	bpf.ALUOpAdd:        asm.Add,
	bpf.ALUOpSub:        asm.Sub,
	bpf.ALUOpMul:        asm.Mul,
	bpf.ALUOpDiv:        asm.Div,
	bpf.ALUOpOr:         asm.Or,
	bpf.ALUOpAnd:        asm.And,
	bpf.ALUOpShiftLeft:  asm.LSh,
	bpf.ALUOpShiftRight: asm.RSh,
	bpf.ALUOpMod:        asm.Mod,
	bpf.ALUOpXor:        asm.Xor,
}

// bpf sizes to ebpf
var sizeToEBPF = map[int]asm.Size{
	1: asm.Byte,
	2: asm.Half,
	4: asm.Word,
}

// Copyright 2022 The Inspektor Gadget authors
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

//go:build !localgadget

package compiler

import (
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// Partly copied from https://github.com/cloudflare/xdpcap/blob/12307bddefb8a850f940cbbf46836760c1444138/internal/tcpdump.go

func TcpdumpExprToBPF(filterExpr string, linkType layers.LinkType, snapLen int) ([]bpf.RawInstruction, error) {
	// We treat any != 0 filter return code as a match
	insns, err := pcap.CompileBPFFilter(linkType, snapLen, filterExpr)
	if err != nil {
		return nil, fmt.Errorf("compiling expression to BPF: %w", err)
	}
	return bpf.Assemble(pcapInsnToX(insns))
}

func pcapInsnToX(insns []pcap.BPFInstruction) []bpf.Instruction {
	xInsns := make([]bpf.Instruction, len(insns))

	for i, insn := range insns {
		xInsns[i] = bpf.RawInstruction{
			Op: insn.Code,
			Jt: insn.Jt,
			Jf: insn.Jf,
			K:  insn.K,
		}.Disassemble()
	}

	return xInsns
}

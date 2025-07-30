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

// Package libpcap_compiler compiles libpcap filter expressions into eBPF
// code. This package contains parts from:
// https://github.com/jschwinger233/elibpcap/
// https://github.com/mozillazg/ptcpdump/
package libpcap_compiler

import (
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

const (
	RejectAllExpr = "__reject_all__"
)

type StackOffset int

const (
	BpfReadKernelOffset StackOffset = -8 * (iota + 1)
	R1Offset
	R2Offset
	R3Offset
	R4Offset
	R5Offset
	AvailableOffset
)

/*
CompileEbpf compiles a libpcap filter expression to eBPF instructions
*/
func CompileEbpf(expr string, fname string, l2 bool) (insts asm.Instructions, err error) {
	if expr == RejectAllExpr {
		return asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}, nil
	}
	cbpfInsts, err := CompileCbpf(expr, l2)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, cbpfc.EBPFOpts{
		// skb->data is at r4, skb->data_end is at r5.
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      asm.R0,
		ResultLabel: "_result_" + fname,
		// _skb is at R0, __skb is at R1, ___skb is at R2.
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "_prefix_" + fname,
		StackOffset: -int(AvailableOffset),
	})
	if err != nil {
		return
	}

	return append(ebpfInsts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol("_result_"+fname), // r1 = 0 (_skb)
		asm.Mov.Imm(asm.R2, 0),                              // r2 = 0 (__skb)
		asm.Mov.Imm(asm.R3, 0),                              // r3 = 0 (___skb)
		asm.Mov.Reg(asm.R4, asm.R0),                         // r4 = $result (data)
		asm.Mov.Imm(asm.R5, 0),                              // r5 = 0 (data_end)
	), nil
}

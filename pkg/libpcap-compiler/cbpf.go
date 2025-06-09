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

package libpcap_compiler

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/net/bpf"
)

// C string utilities
func cString(s string) *byte {
	bs := make([]byte, len(s)+1)
	copy(bs, s)
	bs[len(s)] = 0
	return &bs[0]
}

func goString(p *byte) string {
	if p == nil {
		return ""
	}

	var bytes []byte
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)))
		if b == 0 {
			break
		}
		bytes = append(bytes, b)
	}
	return string(bytes)
}

// libpcapDynamic handles dynamic loading of libpcap functions
type libpcapDynamic struct {
	// libpcap handle
	handle uintptr

	// libpcap functions
	pcapOpenDead func(linktype int, snaplen int) uintptr
	pcapClose    func(p uintptr)
	pcapCompile  func(p uintptr, fp unsafe.Pointer, str *byte, optimize int, netmask uint32) int
	pcapFreecode func(fp unsafe.Pointer)
	pcapGeterr   func(p uintptr) *byte

	// Singleton pattern
	once sync.Once
	err  error
}

// pcapBpfProgramDynamic is the Go equivalent of struct bpf_program from pcap.h
type pcapBpfProgramDynamic struct {
	bf_len   uint32
	bf_insns uintptr
}

// pcapBpfInsnDynamic is the Go equivalent of struct bpf_insn from pcap.h
type pcapBpfInsnDynamic struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// Constants from pcap.h
const (
	DLT_EN10MB           = 1
	DLT_RAW              = 12
	PCAP_NETMASK_UNKNOWN = 0xffffffff
	PCAP_ERROR           = -1
	MAXIMUM_SNAPLEN      = 262144

	// Constants for buffer sizes
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
)

// Global instance of libpcapDynamic
var libpcap = &libpcapDynamic{}

// init initializes the libpcap dynamic loader
func (l *libpcapDynamic) init() error {
	l.once.Do(func() {
		// Try to load libpcap.so
		var err error

		libpcapPaths := []string{"libpcap.so", "libpcap.so.1", "libpcap.so.0"}

		// Try each path until one works
		for _, path := range libpcapPaths {
			l.handle, err = purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
			if err == nil {
				break
			}
		}

		if err != nil {
			l.err = fmt.Errorf("loading libpcap: %w", err)
			return
		}

		// Load functions
		var pcapOpenDeadSym uintptr
		pcapOpenDeadSym, err = purego.Dlsym(l.handle, "pcap_open_dead")
		if err != nil {
			l.err = fmt.Errorf("loading pcap_open_dead: %w", err)
			return
		}
		purego.RegisterFunc(&l.pcapOpenDead, pcapOpenDeadSym)

		var pcapCloseSym uintptr
		pcapCloseSym, err = purego.Dlsym(l.handle, "pcap_close")
		if err != nil {
			l.err = fmt.Errorf("loading pcap_close: %w", err)
			return
		}
		purego.RegisterFunc(&l.pcapClose, pcapCloseSym)

		var pcapCompileSym uintptr
		pcapCompileSym, err = purego.Dlsym(l.handle, "pcap_compile")
		if err != nil {
			l.err = fmt.Errorf("loading pcap_compile: %w", err)
			return
		}
		purego.RegisterFunc(&l.pcapCompile, pcapCompileSym)

		var pcapFreecodeSym uintptr
		pcapFreecodeSym, err = purego.Dlsym(l.handle, "pcap_freecode")
		if err != nil {
			l.err = fmt.Errorf("loading pcap_freecode: %w", err)
			return
		}
		purego.RegisterFunc(&l.pcapFreecode, pcapFreecodeSym)

		var pcapGeterrSym uintptr
		pcapGeterrSym, err = purego.Dlsym(l.handle, "pcap_geterr")
		if err != nil {
			l.err = fmt.Errorf("loading pcap_geterr: %w", err)
			return
		}
		purego.RegisterFunc(&l.pcapGeterr, pcapGeterrSym)
	})

	return l.err
}

// CompileCbpf compiles a libpcap expression into cbpf instructions
func CompileCbpf(expr string, l2 bool) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	// Initialize libpcap
	if err = libpcap.init(); err != nil {
		return nil, fmt.Errorf("initializing libpcap: %w", err)
	}

	pcapType := DLT_RAW
	if l2 {
		pcapType = DLT_EN10MB
	}

	pcap := libpcap.pcapOpenDead(pcapType, MAXIMUM_SNAPLEN)
	if pcap == 0 {
		return nil, fmt.Errorf("calling pcap_open_dead: %+v", PCAP_ERROR)
	}
	defer libpcap.pcapClose(pcap)

	cexpr := cString(expr)

	var bpfProg pcapBpfProgramDynamic
	if libpcap.pcapCompile(pcap, unsafe.Pointer(&bpfProg), cexpr, 1, PCAP_NETMASK_UNKNOWN) < 0 {
		errStr := goString(libpcap.pcapGeterr(pcap))
		return nil, fmt.Errorf("calling pcap_compile '%s': %+v", expr, errStr)
	}
	defer libpcap.pcapFreecode(unsafe.Pointer(&bpfProg))

	// Convert the compiled program to bpf.Instruction slice
	insns := (*[bpfInstructionBufferSize]pcapBpfInsnDynamic)(unsafe.Pointer(bpfProg.bf_insns))
	for i := uint32(0); i < bpfProg.bf_len; i++ {
		v := insns[i]
		insts = append(insts, bpf.RawInstruction{
			Op: uint16(v.code),
			Jt: uint8(v.jt),
			Jf: uint8(v.jf),
			K:  uint32(v.k),
		}.Disassemble())
	}

	return
}

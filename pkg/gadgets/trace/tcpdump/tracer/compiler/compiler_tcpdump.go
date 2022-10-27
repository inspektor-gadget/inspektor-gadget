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

//go:build localgadget

package compiler

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func TcpdumpExprToBPF(filterExpr string, linkType layers.LinkType, snapLen int) ([]bpf.RawInstruction, error) {
	if linkType != layers.LinkTypeEthernet {
		return nil, errors.New("unsupported linkType")
	}

	// We'll use an installed tcpdump to compile the filter
	cmd := exec.Command("tcpdump", "-ddd", "-s", strconv.Itoa(snapLen), filterExpr)

	var b bytes.Buffer
	cmd.Stdout = &b
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("compiling filter using tcpdump binary: %w", err)
	}

	// Read lines
	lines := strings.Split(strings.Replace(b.String(), "\r", "", -1), "\n")
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

	if len(xInsns) != count {
		return nil, fmt.Errorf("instruction count does not match number of instructions given: count: %d, instructions found: %d", count, len(xInsns))
	}

	return bpf.Assemble(xInsns)
}

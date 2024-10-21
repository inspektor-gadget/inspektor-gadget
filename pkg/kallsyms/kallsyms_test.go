// Copyright 2023 The Inspektor Gadget authors
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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
)

func resetState() {
	symbolsMap = map[string]uint64{}
	triedGetAddr = map[string]error{}
}

func TestCustomKAllSyms(t *testing.T) {
	kAllSymsStr := strings.Join([]string{
		"0000000000000000 A fixed_percpu_data",
		"ffffffffb4231f40 D bpf_prog_fops",
		"ffffffffb43723e0 d socket_file_ops",
	}, "\n")

	kAllSymsReader := strings.NewReader(kAllSymsStr)
	kAllSyms, err := NewKAllSymsFromReader(kAllSymsReader)
	require.Nil(t, err, "NewKAllSymsFromReader failed: %v", err)
	require.True(t, kAllSyms.SymbolExists("bpf_prog_fops"),
		"SymbolExists should have found bpf_prog_fops")
	require.False(t, kAllSyms.SymbolExists("abcde_bad_name"),
		"SymbolExists should not have found abcde_bad_name")

	lookupByInstructionPointerTests := []struct {
		instructionPointer uint64
		expectedSymbol     string
	}{
		{0, "fixed_percpu_data"},
		{0xffffffffb4231f39, "fixed_percpu_data"},
		{0xffffffffb4231f40, "bpf_prog_fops"},
		// TODO: is it correct? should it be bpf_prog_fops?
		{0xffffffffb4231f41, "bpf_prog_fops"},
		{0xffffffffb43723df, "bpf_prog_fops"},
		{0xffffffffb43723e0, "socket_file_ops"},
		{0xffffffffb43723e1, "socket_file_ops"},
	}
	for _, tt := range lookupByInstructionPointerTests {
		require.Equal(t, tt.expectedSymbol, kAllSyms.LookupByInstructionPointer(tt.instructionPointer),
			"LookupByInstructionPointer(0x%x)", tt.instructionPointer)
	}
}

func TestRealKAllSyms(t *testing.T) {
	utilstest.RequireRoot(t)
	utilstest.RequireFileContains(t, "/proc/kallsyms", "bpf_prog_fops")
	utilstest.RequireFileContains(t, "/proc/kallsyms", "socket_file_ops")

	kAllSyms, err := NewKAllSyms()
	require.Nil(t, err, "NewKAllSyms failed: %v", err)
	require.True(t, kAllSyms.SymbolExists("bpf_prog_fops"),
		"SymbolExists should have found bpf_prog_fops")
	require.False(t, kAllSyms.SymbolExists("abcde_bad_name"),
		"SymbolExists should not have found abcde_bad_name")

	addr, ok := kAllSyms.symbolsMap["bpf_prog_fops"]
	require.True(t, ok, "bpf_prog_fops not found in symbolsMap")
	// /proc/kallsyms contains the address 0 without CAP_SYSLOG.
	// Since we use RequireRoot, it should not happen.
	require.NotEqual(t, 0, addr, "bpf_prog_fops has a zero address")
}

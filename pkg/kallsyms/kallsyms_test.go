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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
)

func TestCustomKAllSymsInstructionPointer(t *testing.T) {
	kAllSymsStr := strings.Join([]string{
		"0000000000000000 A fixed_percpu_data",
		"ffffffffb4231f40 D bpf_prog_fops",
		"ffffffffb43723e0 d socket_file_ops",
	}, "\n")

	kAllSymsReader := strings.NewReader(kAllSymsStr)
	kAllSyms, err := NewKAllSymsFromReader(kAllSymsReader)
	require.Nil(t, err, "NewKAllSymsFromReader failed: %v", err)

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

func TestCustomKAllSymsParsing(t *testing.T) {
	kAllSymsStr := strings.Join([]string{
		"0000000000000000 A fixed_percpu_data",
		"ffffffffb4231f40 D bpf_prog_fops",
		"ffffffffb43723e0 d socket_file_ops",
		"ffffffff906e97e0 T security_bprm_check",
		"ffffffffc1b26010 T veth_init	[veth]",
		"ffffffffc1cb5010 T netem_module_init	[sch_netem]",
		"",
	}, "\n")

	tests := []struct {
		symbol     string
		expectErr  bool
		expectAddr uint64
		expectKmod string
	}{
		{
			symbol:     "bpf_prog_fops",
			expectErr:  false,
			expectAddr: 0xffffffffb4231f40,
			expectKmod: "",
		},
		{
			symbol:     "socket_file_ops",
			expectErr:  false,
			expectAddr: 0xffffffffb43723e0,
			expectKmod: "",
		},
		{
			symbol:     "veth_init",
			expectErr:  false,
			expectAddr: 0xffffffffc1b26010,
			expectKmod: "veth",
		},
		{
			symbol:     "netem_module_init",
			expectErr:  false,
			expectAddr: 0xffffffffc1cb5010,
			expectKmod: "sch_netem",
		},
		{
			symbol:     "abcde_bad_name",
			expectErr:  true,
			expectAddr: 0,
			expectKmod: "",
		},
	}

	for _, test := range tests {
		t.Run(test.symbol, func(t *testing.T) {
			r := strings.NewReader(kAllSymsStr)
			addr, kmod, err := kernelSymbolAddressFromReader(r, test.symbol)

			if test.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.expectAddr, addr, "addr")
			require.Equal(t, test.expectKmod, kmod, "kmod")
		})
	}
}

func TestRealKAllSymsParsing(t *testing.T) {
	path := "/proc/kallsyms"
	utilstest.RequireRoot(t)
	utilstest.RequireFileContains(t, path, "bpf_prog_fops")
	utilstest.RequireFileContains(t, path, "socket_file_ops")

	type testT struct {
		name           string
		symbol         string
		expectedKmod   string
		expectedExists bool
	}

	tests := []testT{
		{
			name:           "simple_symbol1",
			symbol:         "bpf_prog_fops",
			expectedKmod:   "",
			expectedExists: true,
		},
		{
			name:           "simple_symbol2",
			symbol:         "socket_file_ops",
			expectedKmod:   "",
			expectedExists: true,
		},
		{
			name:           "symbol_from_veth_kmod",
			symbol:         "veth_init",
			expectedKmod:   "veth",
			expectedExists: true,
		},
		{
			name:           "symbol_from_netem_kmod",
			symbol:         "netem_module_init",
			expectedKmod:   "sch_netem",
			expectedExists: true,
		},
		{
			name:           "symbol_from_overlay_kmod",
			symbol:         "ovl_inode_init",
			expectedKmod:   "overlay",
			expectedExists: true,
		},
		{
			name:           "nonexistent_symbol",
			symbol:         "abcde_bad_name",
			expectedKmod:   "",
			expectedExists: false,
		},
	}

	kallsymsBytes, err := os.ReadFile(path)
	require.Nil(t, err, "Failed to read %q: %s", path, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.expectedExists &&
				test.expectedKmod != "" &&
				!strings.Contains(string(kallsymsBytes), test.expectedKmod) {
				t.Skipf("Test requires kernel module %q", test.expectedKmod)
			}

			require.Equal(t, test.expectedExists, SymbolExists(test.symbol), "exists")
			addr, kmod, err := KernelSymbolAddress(test.symbol)
			if test.expectedExists {
				require.NoError(t, err)
				require.NotEqual(t, uint64(0), addr, "addr")
				require.Equal(t, test.expectedKmod, kmod, "kmod")
			} else {
				require.Error(t, err)
				require.Equal(t, uint64(0), addr, "addr")
				require.Equal(t, "", kmod, "kmod")
			}
		})
	}
}

// BenchmarkKernelSymbolAddressJITParsing searches for the symbol while
// reading the kallsyms file
func BenchmarkKernelSymbolAddressJITParsing(b *testing.B) {
	utilstest.RequireRoot(b)
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		exists := SymbolExists("security_bprm_check")
		require.Equal(b, true, exists, "exists")
	}
}

// BenchmarkKernelSymbolAddressPreLoading loads the full kallsyms before
// looking up the symbol
func BenchmarkKernelSymbolAddressPreLoading(b *testing.B) {
	utilstest.RequireRoot(b)
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		k, err := NewKAllSyms()
		require.NoError(b, err)
		require.NotNil(b, k)
		_, exists := k.symbolsMap["security_bprm_check"]
		require.Equal(b, true, exists)
	}
}

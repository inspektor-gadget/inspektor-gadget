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
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
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
		name               string
		instructionPointer uint64
		expectedSymbol     string
	}{
		{
			name:               "exact_match_start",
			instructionPointer: 0,
			expectedSymbol:     "fixed_percpu_data",
		},
		{
			name:               "middle_of_first_range",
			instructionPointer: 0xffffffffb4231f39,
			expectedSymbol:     "fixed_percpu_data",
		},
		{
			name:               "exact_match_middle",
			instructionPointer: 0xffffffffb4231f40,
			expectedSymbol:     "bpf_prog_fops",
		},
		{
			name:               "middle_of_second_range",
			instructionPointer: 0xffffffffb4231f41,
			expectedSymbol:     "bpf_prog_fops",
		},
		{
			name:               "end_of_second_range",
			instructionPointer: 0xffffffffb43723df,
			expectedSymbol:     "bpf_prog_fops",
		},
		{
			name:               "start_of_last_range",
			instructionPointer: 0xffffffffb43723e0,
			expectedSymbol:     "socket_file_ops",
		},
		{
			name:               "after_last_symbol",
			instructionPointer: 0xffffffffb43723e1,
			expectedSymbol:     "socket_file_ops",
		},
	}
	for _, tt := range lookupByInstructionPointerTests {
		t.Run(tt.name, func(t *testing.T) {
			result := kAllSyms.LookupByInstructionPointer(tt.instructionPointer)
			assert.Equal(t, tt.expectedSymbol, result,
				"LookupByInstructionPointer(0x%x)", tt.instructionPointer)
		})
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
		name       string
		symbol     string
		expectErr  bool
		expectAddr uint64
		expectKmod string
	}{
		{
			name:       "core_kernel_symbol",
			symbol:     "bpf_prog_fops",
			expectErr:  false,
			expectAddr: 0xffffffffb4231f40,
			expectKmod: "",
		},
		{
			name:       "another_core_symbol",
			symbol:     "socket_file_ops",
			expectErr:  false,
			expectAddr: 0xffffffffb43723e0,
			expectKmod: "",
		},
		{
			name:       "veth_module_symbol",
			symbol:     "veth_init",
			expectErr:  false,
			expectAddr: 0xffffffffc1b26010,
			expectKmod: "veth",
		},
		{
			name:       "netem_module_symbol",
			symbol:     "netem_module_init",
			expectErr:  false,
			expectAddr: 0xffffffffc1cb5010,
			expectKmod: "sch_netem",
		},
		{
			name:       "nonexistent_symbol",
			symbol:     "abcde_bad_name",
			expectErr:  true,
			expectAddr: 0,
			expectKmod: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := strings.NewReader(kAllSymsStr)
			addr, kmod, err := kernelSymbolAddressFromReader(r, test.symbol)

			if test.expectErr {
				assert.Error(t, err, "Should return error for invalid symbol %s", test.symbol)
			} else {
				assert.NoError(t, err, "Should successfully resolve symbol %s", test.symbol)
			}

			assert.Equal(t, test.expectAddr, addr, "Address for symbol %s should match expected value", test.symbol)
			assert.Equal(t, test.expectKmod, kmod, "Kernel module for symbol %s should match expected value", test.symbol)
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
			symbol:         "veth_open",
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
				t.Skipf("Test requires kernel module %q to be loaded", test.expectedKmod)
			}

			assert.Equal(t, test.expectedExists, SymbolExists(test.symbol),
				"Symbol %s existence check should match expected value", test.symbol)

			addr, kmod, err := KernelSymbolAddress(test.symbol)
			if test.expectedExists {
				assert.NoError(t, err, "Should successfully resolve existing symbol %s", test.symbol)
				assert.NotEqual(t, uint64(0), addr, "Address for existing symbol %s should not be zero", test.symbol)
				assert.Equal(t, test.expectedKmod, kmod, "Kernel module for symbol %s should match expected", test.symbol)
			} else {
				assert.Error(t, err, "Should fail to resolve non-existent symbol %s", test.symbol)
				assert.Equal(t, uint64(0), addr, "Address for non-existent symbol should be zero")
				assert.Equal(t, "", kmod, "Kernel module for non-existent symbol should be empty")
			}
		})
	}
}

func TestNewKAllSymsFromReaderErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{
			name:        "invalid_format_less_fields",
			input:       "0000000000000000 A",
			expectedErr: "line \"0000000000000000 A\" has less than 3 fields",
		},
		{
			name:        "invalid_address",
			input:       "INVALID_ADDR A fixed_percpu_data",
			expectedErr: "strconv.ParseUint",
		},
		{
			name:        "malformed_line_no_fields",
			input:       "0000000000000000",
			expectedErr: "line \"0000000000000000\" has less than 3 fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			_, err := NewKAllSymsFromReader(reader)
			assert.Error(t, err, "Should return error for malformed input")
			assert.Contains(t, err.Error(), tt.expectedErr,
				"Error message should contain expected text for malformed input case: %s", tt.name)
		})
	}
}

func TestSymbolExistsWithEmptySymbol(t *testing.T) {
	exists := SymbolExists("")
	assert.False(t, exists, "Empty symbol should not exist in kallsyms")
}

// MockVar represents a mock implementation of ebpf.Var for testing
type MockVar struct {
	value interface{}
}

func (v *MockVar) Set(value interface{}) error {
	v.value = value
	return nil
}

// mockSymbolResolver implements symbolResolver interface for testing
type mockSymbolResolver struct {
	resolveFunc func(symbol string) (uint64, error)
}

func (m *mockSymbolResolver) resolve(symbol string) (uint64, error) {
	return m.resolveFunc(symbol)
}

func TestSpecUpdateAddressesEmptySymbols(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps:      make(map[string]*ebpf.MapSpec),
		Programs:  make(map[string]*ebpf.ProgramSpec),
		Variables: make(map[string]*ebpf.VariableSpec),
	}
	err := SpecUpdateAddresses(spec, []string{})
	assert.NoError(t, err, "Should handle empty symbols list without error")
}

func TestSpecUpdateAddressesSymbolResolution(t *testing.T) {
	// Reset global state before each test
	symbolsMap = make(map[string]uint64)
	triedGetAddr = make(map[string]error)

	t.Run("all_resolvers_fail", func(t *testing.T) {
		const (
			firstResolverError  = "first resolver failed"
			secondResolverError = "second resolver failed"
		)

		resolver1 := &mockSymbolResolver{
			resolveFunc: func(symbol string) (uint64, error) {
				return 0, errors.New(firstResolverError)
			},
		}
		resolver2 := &mockSymbolResolver{
			resolveFunc: func(symbol string) (uint64, error) {
				return 0, errors.New(secondResolverError)
			},
		}

		spec := &ebpf.CollectionSpec{
			Variables: map[string]*ebpf.VariableSpec{
				"missing_symbol_addr": {},
			},
		}

		err := specUpdateAddresses(
			[]symbolResolver{resolver1, resolver2},
			spec,
			[]string{"missing_symbol"},
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), secondResolverError, "Only the error of the last resolver should be returned")

		// Verify error is cached
		cachedErr, exists := triedGetAddr["missing_symbol"]
		assert.True(t, exists, "Error should be cached in triedGetAddr map")
		assert.Equal(t, err, cachedErr, "Cached error should match the original error")
	})

	t.Run("resolver_error_and_caching", func(t *testing.T) {
		// First call - actual resolver error
		failResolver := &mockSymbolResolver{
			resolveFunc: func(symbol string) (uint64, error) {
				return 0, fmt.Errorf("resolver error: symbol not found")
			},
		}

		spec := &ebpf.CollectionSpec{
			Variables: map[string]*ebpf.VariableSpec{
				"symbol1_addr": {},
			},
		}

		// First attempt - resolver fails
		err := specUpdateAddresses(
			[]symbolResolver{failResolver},
			spec,
			[]string{"symbol1"},
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "resolver error: symbol not found")

		// Second attempt - should return cached error without calling resolver
		secondResolver := &mockSymbolResolver{
			resolveFunc: func(symbol string) (uint64, error) {
				t.Fatal("resolver should not be called when error is cached")
				return 0, nil
			},
		}

		err = specUpdateAddresses(
			[]symbolResolver{secondResolver},
			spec,
			[]string{"symbol1"},
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "resolver error: symbol not found")
	})
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

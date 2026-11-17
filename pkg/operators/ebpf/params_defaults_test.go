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

package ebpfoperator

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// rodataSpec returns a spec equivalent to the following eBPF program:
//
//	const volatile bool myparam = true;
//	GADGET_PARAM(myparam);
func rodataSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()

	boolType := &btf.Int{Name: "_Bool", Size: 1, Encoding: btf.Bool}
	v := &btf.Var{
		Name:    "myparam",
		Type:    &btf.Const{Type: &btf.Volatile{Type: boolType}},
		Linkage: btf.GlobalVar,
	}
	datasec := &btf.Datasec{
		Name: ".rodata",
		Size: 1,
		Vars: []btf.VarSecinfo{{Type: v, Size: 1}},
	}

	builder, err := btf.NewBuilder([]btf.Type{datasec}, nil)
	require.NoError(t, err)
	raw, err := builder.Marshal(nil, nil)
	require.NoError(t, err)
	types, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	require.NoError(t, err)

	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			".rodata": {
				Name:     ".rodata",
				Value:    datasec,
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: []byte{1}}},
			},
		},
		Types: types,
	}
}

func TestParamDefaultValue(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		expected string
	}{
		{
			name:     "metadata default wins over the eBPF one",
			metadata: `params: {ebpf: {myparam: {defaultValue: "false"}}}`,
			expected: "false",
		},
		{
			name:     "eBPF default is used when metadata has an empty one",
			metadata: `params: {ebpf: {myparam: {defaultValue: ""}}}`,
			expected: "true",
		},
		{
			name:     "eBPF default is used when metadata has none",
			metadata: `params: {ebpf: {myparam: {key: my-param}}}`,
			expected: "true",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := viper.New()
			config.SetConfigType("yaml")
			require.NoError(t, config.ReadConfig(strings.NewReader(test.metadata)))

			instance := &ebpfInstance{
				logger:         logger.DefaultLogger(),
				gadgetCtx:      gadgetcontext.New(context.Background(), "test"),
				config:         config,
				collectionSpec: rodataSpec(t),
				params:         make(map[string]*param),
			}

			require.NoError(t, instance.populateParam(nil, "myparam"))
			require.NoError(t, instance.fillParamDefaults())
			require.Equal(t, test.expected, instance.params["myparam"].DefaultValue)
		})
	}
}

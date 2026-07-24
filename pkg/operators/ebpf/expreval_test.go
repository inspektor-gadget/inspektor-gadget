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
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/exprgate"
)

func newTestInstance(t *testing.T) *ebpfInstance {
	t.Helper()
	return &ebpfInstance{
		logger:       logger.DefaultLogger(),
		mapOnlyIf:    make(map[string]*exprgate.Program),
		progAttachTo: make(map[string]*exprgate.Program),
	}
}

func TestPoisonMapReferences(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"prog": {
				Instructions: asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.LoadMapPtr(asm.R1, 0).WithReference("gatedmap"),
					asm.LoadMapPtr(asm.R2, 0).WithReference("othermap"),
					asm.LoadMapPtr(asm.R3, 0).WithReference("gatedmap"),
					asm.Return(),
				},
			},
		},
	}
	i := newTestInstance(t)
	i.collectionSpec = spec

	n := i.poisonMapReferences("gatedmap")
	assert.Equal(t, 2, n, "should poison both references to gatedmap")

	ins := spec.Programs["prog"].Instructions
	// Poisoned instructions: illegal DWord immediate load into R10.
	for _, idx := range []int{1, 3} {
		assert.Equal(t, asm.LoadImmOp(asm.DWord), ins[idx].OpCode, "instruction %d op", idx)
		assert.Equal(t, asm.R10, ins[idx].Dst, "instruction %d dst", idx)
		assert.Equal(t, int64(poisonSentinel), ins[idx].Constant, "instruction %d constant", idx)
		assert.False(t, ins[idx].IsLoadFromMap(), "instruction %d must no longer load from a map", idx)
	}
	// The unrelated map reference is untouched.
	assert.True(t, ins[2].IsLoadFromMap())
	assert.Equal(t, "othermap", ins[2].Reference())
}

func TestGateMapsDropsWhenFalse(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"gatedmap": {Name: "gatedmap"},
			"keptmap":  {Name: "keptmap"},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"prog": {
				Instructions: asm.Instructions{
					asm.LoadMapPtr(asm.R1, 0).WithReference("gatedmap"),
					asm.Return(),
				},
			},
		},
	}
	i := newTestInstance(t)
	i.collectionSpec = spec
	i.exprEval = exprgate.New(nil, exprgate.KallsymsFuncs{})

	prog, err := i.exprEval.Compile("params.enabled", exprgate.KindOnlyIf, "")
	require.NoError(t, err)
	i.mapOnlyIf["gatedmap"] = prog

	// enabled=false -> map dropped and reference poisoned.
	err = i.gateMaps(nil, map[string]any{"enabled": false}, map[string]any{})
	require.NoError(t, err)
	assert.NotContains(t, spec.Maps, "gatedmap", "gated map should be dropped")
	assert.Contains(t, spec.Maps, "keptmap")
	assert.False(t, spec.Programs["prog"].Instructions[0].IsLoadFromMap(), "reference should be poisoned")
	require.Len(t, i.gatedMaps, 1)
	assert.Equal(t, "gatedmap", i.gatedMaps[0].name)
}

func TestEvaluateDefinesChained(t *testing.T) {
	i := newTestInstance(t)
	i.exprEval = exprgate.New([]string{"a", "b"}, exprgate.KallsymsFuncs{})

	progA, err := i.exprEval.Compile("params.n + 1", exprgate.KindDefine, "a")
	require.NoError(t, err)
	progB, err := i.exprEval.Compile("a * 2", exprgate.KindDefine, "b")
	require.NoError(t, err)
	i.exprDefines = []exprBinding{{name: "a", prog: progA}, {name: "b", prog: progB}}

	defines, err := i.evaluateDefines(map[string]any{"n": int64(10)})
	require.NoError(t, err)
	assert.EqualValues(t, 11, defines["a"])
	assert.EqualValues(t, 22, defines["b"], "define b should see the value of earlier define a")
}

func TestGateMapsKeepsWhenTrue(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"gatedmap": {Name: "gatedmap"},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"prog": {
				Instructions: asm.Instructions{
					asm.LoadMapPtr(asm.R1, 0).WithReference("gatedmap"),
					asm.Return(),
				},
			},
		},
	}
	i := newTestInstance(t)
	i.collectionSpec = spec
	i.exprEval = exprgate.New(nil, exprgate.KallsymsFuncs{})

	prog, err := i.exprEval.Compile("params.enabled", exprgate.KindOnlyIf, "")
	require.NoError(t, err)
	i.mapOnlyIf["gatedmap"] = prog

	// enabled=true -> map kept, reference intact.
	err = i.gateMaps(nil, map[string]any{"enabled": true}, map[string]any{})
	require.NoError(t, err)
	assert.Contains(t, spec.Maps, "gatedmap", "map should be kept")
	assert.True(t, spec.Programs["prog"].Instructions[0].IsLoadFromMap(), "reference should be intact")
	assert.Empty(t, i.gatedMaps)
}

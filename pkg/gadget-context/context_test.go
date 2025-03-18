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

package gadgetcontext

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// newSimpleOperator takes a name, a priority and a pointer to a string that the operator writes its name
// to during instantiation
func newSimpleOperator(name string, priority int, write *string, cancel func()) operators.DataOperator {
	return simple.New(name, simple.WithPriority(priority),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			*write += name
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			cancel()
			return nil
		}),
	)
}

func TestOperatorOrder(t *testing.T) {
	type operatorConfig struct {
		name     string
		priority int
	}
	type testCase struct {
		name          string
		operators     []operatorConfig
		expectedOrder string
	}
	testCases := []testCase{
		{
			name: "distinct priority",
			operators: []operatorConfig{
				{name: "b", priority: 1},
				{name: "a", priority: 0},
			},
			expectedOrder: "ab",
		},
		{
			name: "same priority",
			operators: []operatorConfig{
				{name: "b", priority: 0},
				{name: "a", priority: 0},
				{name: "c", priority: 0},
			},
			expectedOrder: "abc",
		},
	}
	for _, tc := range testCases {
		out := ""
		t.Run("", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var ops []operators.DataOperator
			for _, op := range tc.operators {
				ops = append(ops, newSimpleOperator(op.name, op.priority, &out, cancel))
			}
			err := New(ctx, "", WithDataOperators(ops...)).Run(nil)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOrder, out)
		})
	}
}

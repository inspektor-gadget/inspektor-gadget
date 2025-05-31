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
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type fakeOperator struct {
	name     string
	priority int

	// list of methods that will fail
	fails []string

	// list of methods called which didn't return an error
	called *[]string
}

func (s *fakeOperator) Name() string {
	return s.name
}

func (s *fakeOperator) Init(*params.Params) error {
	return nil
}

func (s *fakeOperator) GlobalParams() api.Params {
	return nil
}

func (s *fakeOperator) InstanceParams() api.Params {
	return nil
}

func (s *fakeOperator) InstantiateDataOperator(operators.GadgetContext, api.ParamValues) (operators.DataOperatorInstance, error) {
	return s, nil
}

func (s *fakeOperator) Priority() int {
	return s.priority
}

func (s *fakeOperator) runMethod(name string) error {
	if slices.Contains(s.fails, name) {
		return errors.New("needs to fail")
	}

	*s.called = append(*s.called, s.name+"_"+name)

	return nil
}

func (s *fakeOperator) PreStart(operators.GadgetContext) error {
	return s.runMethod("prestart")
}

func (s *fakeOperator) Start(operators.GadgetContext) error {
	return s.runMethod("start")
}

func (s *fakeOperator) Stop(operators.GadgetContext) error {
	return s.runMethod("stop")
}

func (s *fakeOperator) PostStop(operators.GadgetContext) error {
	return s.runMethod("poststop")
}

func (s *fakeOperator) Close(operators.GadgetContext) error {
	return s.runMethod("close")
}

func TestRun(t *testing.T) {
	type testCase struct {
		name          string
		ops           []*fakeOperator
		expectedCalls []string
		expectedErr   bool
	}

	tests := []testCase{
		// all operations should be called if there is not any error
		{
			name: "single_operator_all_work",
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
				},
			},
			expectedCalls: []string{
				"op1_prestart",
				"op1_start",
				"op1_stop",
				"op1_poststop",
				"op1_close",
			},
		},
		// close should always be called if another operation fails
		{
			name:        "single_operator_prestart_fails",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"prestart"},
				},
			},
			expectedCalls: []string{
				"op1_close",
			},
		},
		{
			name:        "single_operator_start_fails",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"start"},
				},
			},
			expectedCalls: []string{
				"op1_prestart",
				"op1_close",
			},
		},
		{
			name:        "single_operator_stop_fails",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"stop"},
				},
			},
			expectedCalls: []string{
				"op1_prestart",
				"op1_start",
				"op1_poststop", // TODO: Ideally poststop shouldn't be called if stop failed
				"op1_close",
			},
		},
		{
			name:        "single_operator_poststop_fails",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"poststop"},
				},
			},
			expectedCalls: []string{
				"op1_prestart",
				"op1_start",
				"op1_stop",
				"op1_close",
			},
		},
		{
			name: "multiple_operators_all_work",
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
				},
				{
					name:     "op2",
					priority: 2,
				},
			},
			expectedCalls: []string{
				// prestart and start in order
				"op1_prestart",
				"op2_prestart",

				"op1_start",
				"op2_start",

				// stop, prestop and close in inverse order
				"op2_stop",
				"op1_stop",

				"op2_poststop",
				"op1_poststop",

				"op2_close",
				"op1_close",
			},
		},
		{
			name:        "multiple_operators_with_prestart_failure",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"prestart"},
				},
				{
					name:     "op2",
					priority: 2,
				},
			},
			expectedCalls: []string{
				"op2_close",
				"op1_close",
			},
		},
		{
			name:        "multiple_operators_with_start_failure",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"start"},
				},
				{
					name:     "op2",
					priority: 2,
				},
			},
			expectedCalls: []string{
				"op1_prestart",
				"op2_prestart",

				// close is always called
				"op2_close",
				"op1_close",
			},
		},
		{
			name:        "multiple_operators_with_start_failure_2",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
				},
				{
					name:     "op2",
					priority: 2,
					fails:    []string{"start"},
				},
			},
			expectedCalls: []string{
				"op1_prestart",
				"op2_prestart",

				"op1_start",

				// stop and poststop should be called on op1 as it was succesfully started
				"op1_stop",
				"op1_poststop",

				"op2_close",
				"op1_close",
			},
		},
		// a failure on stop or prestop shouldn't prevent the other operator to be stopped
		{
			name:        "multiple_operators_with_stop_failure",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"stop"},
				},
				{
					name:     "op2",
					priority: 2,
				},
			},
			expectedCalls: []string{
				// prestart and start in order
				"op1_prestart",
				"op2_prestart",

				"op1_start",
				"op2_start",

				// stop, pre stop and close in inverse order
				"op2_stop",

				"op2_poststop",
				"op1_poststop",

				"op2_close",
				"op1_close",
			},
		},
		{
			name:        "multiple_operators_with_poststop_failure",
			expectedErr: true,
			ops: []*fakeOperator{
				{
					name:     "op1",
					priority: 1,
					fails:    []string{"poststop"},
				},
				{
					name:     "op2",
					priority: 2,
				},
			},
			expectedCalls: []string{
				// prestart and start in order
				"op1_prestart",
				"op2_prestart",

				"op1_start",
				"op2_start",

				// stop, pre stop and close in inverse order
				"op2_stop",
				"op1_stop",

				"op2_poststop",

				"op2_close",
				"op1_close",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			called := []string{}

			ops := make([]operators.DataOperator, 0, len(test.ops))
			for _, op := range test.ops {
				op.called = &called
				ops = append(ops, op)
			}
			opts := WithDataOperators(ops...)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			gadgetCtx := New(ctx, "x.com/do-not-run-this", opts)
			require.NotNil(t, gadgetCtx)

			err := gadgetCtx.Run(nil)
			if test.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.expectedCalls, called)
		})
	}
}

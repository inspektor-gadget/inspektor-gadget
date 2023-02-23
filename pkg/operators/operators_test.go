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

package operators

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type testOp struct {
	name         string
	dependencies []string
}

func (op testOp) Name() string {
	return op.name
}

func (op testOp) Dependencies() []string {
	return op.dependencies
}

func (op testOp) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (op testOp) ParamDescs() params.ParamDescs {
	return nil
}

func (op testOp) Description() string {
	return ""
}

func (op testOp) CanOperateOn(gadgets.GadgetDesc) bool {
	return true
}

func (op testOp) Init(*params.Params) error {
	return nil
}

func (op testOp) Close() error {
	return nil
}

func (op testOp) Instantiate(gadgetContext GadgetContext, gadgetInstance any, perGadgetParams *params.Params) (OperatorInstance, error) {
	return nil, nil
}

func checkDependencies(t *testing.T, ops, sortedOps Operators) {
	assert.Equal(t, len(ops), len(sortedOps), "Length of sorted ops has to be the same as the original ops")

outerLoop:
	for _, op := range ops {
		deps := op.Dependencies()
		for _, sortedOp := range sortedOps {
			if len(deps) == 0 {
				continue outerLoop
			}
			if sortedOp.Name() == op.Name() {
				assert.Failf(t, "Dependencies of %q were not met", op.Name())
			}
			for i, dep := range deps {
				if sortedOp.Name() == dep {
					deps = append(deps[0:i], deps[i+1:]...)
				}
			}
		}
	}
}

func createOp(name string, deps []string) testOp {
	return testOp{name, deps}
}

func Test_SortOperatorsSimple(t *testing.T) {
	ops := Operators{
		createOp("b", []string{"a"}),
		createOp("a", []string{}),
	}

	sortedOps, err := SortOperators(ops)
	if assert.NoError(t, err) {
		checkDependencies(t, ops, sortedOps)
	}
}

func Test_SortOperatorsTwoIncomingDeps(t *testing.T) {
	ops := Operators{
		createOp("b", []string{"a"}),
		createOp("c", []string{"a"}),
		createOp("a", []string{}),
	}

	sortedOps, err := SortOperators(ops)
	if assert.NoError(t, err) {
		checkDependencies(t, ops, sortedOps)
	}
}

func Test_SortOperatorsTwoOutgoingDeps(t *testing.T) {
	ops := Operators{
		createOp("b", []string{"a"}),
		createOp("c", []string{"a", "b"}),
		createOp("a", []string{}),
	}

	sortedOps, err := SortOperators(ops)
	if assert.NoError(t, err) {
		checkDependencies(t, ops, sortedOps)
	}
}

func Test_SortOperatorsTwoOutgoingDepsReversed(t *testing.T) {
	ops := Operators{
		createOp("c", []string{"a", "b"}),
		createOp("b", []string{"a"}),
		createOp("a", []string{}),
	}

	sortedOps, err := SortOperators(ops)
	if assert.NoError(t, err) {
		checkDependencies(t, ops, sortedOps)
	}
}

func Test_SortOperatorsLargaGraph(t *testing.T) {
	ops := Operators{
		createOp("a", []string{}),
		createOp("b", []string{"a"}),
		createOp("c", []string{"a", "h"}),
		createOp("d", []string{"a"}),
		createOp("e", []string{"d", "b"}),
		createOp("f", []string{"h"}),
		createOp("g", []string{"e"}),
		createOp("h", []string{"d"}),
		createOp("i", []string{"g", "f"}),
	}

	sortedOps, err := SortOperators(ops)
	if assert.NoError(t, err) {
		checkDependencies(t, ops, sortedOps)
	}
}

func Test_SortOperatorsMissingDep(t *testing.T) {
	ops := Operators{
		createOp("a", []string{"b"}),
	}

	_, err := SortOperators(ops)
	assert.ErrorContains(t, err, "dependency \""+ops[0].Dependencies()[0]+"\" is not available in operators")
}

func Test_SortOperatorsCyclicDep(t *testing.T) {
	ops := Operators{
		createOp("a", []string{"b"}),
		createOp("b", []string{"a"}),
		createOp("c", []string{"a"}),
	}

	_, err := SortOperators(ops)
	assert.ErrorContains(t, err, "dependency cycle detected")
}

func Test_SortOperatorsLargeCyclicDep(t *testing.T) {
	ops := Operators{
		createOp("a", []string{"b"}),
		createOp("b", []string{"c"}),
		createOp("c", []string{"d"}),
		createOp("d", []string{"e"}),
		createOp("e", []string{"f"}),
		createOp("f", []string{"a"}),
	}

	_, err := SortOperators(ops)
	assert.ErrorContains(t, err, "dependency cycle detected")
}

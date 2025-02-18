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

package operators

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type mockGadgetDesc struct {
	category    string
	name        string
	description string
}

func (m mockGadgetDesc) Name() string                  { return m.name }
func (m mockGadgetDesc) Description() string           { return m.description }
func (m mockGadgetDesc) Category() string              { return m.category }
func (m mockGadgetDesc) Type() gadgets.GadgetType      { return gadgets.TypeTrace }
func (m mockGadgetDesc) ParamDescs() params.ParamDescs { return params.ParamDescs{} }
func (m mockGadgetDesc) Parser() parser.Parser         { return nil }
func (m mockGadgetDesc) EventPrototype() any           { return nil }

type mockOperator struct {
	name         string
	dependencies []string
	canOperateOn bool
	initErr      error
	closeErr     error
	instErr      error
}

func (m *mockOperator) Name() string                         { return m.name }
func (m *mockOperator) Description() string                  { return "mock operator" }
func (m *mockOperator) Dependencies() []string               { return m.dependencies }
func (m *mockOperator) GlobalParamDescs() params.ParamDescs  { return params.ParamDescs{} }
func (m *mockOperator) ParamDescs() params.ParamDescs        { return params.ParamDescs{} }
func (m *mockOperator) CanOperateOn(gadgets.GadgetDesc) bool { return m.canOperateOn }
func (m *mockOperator) Init(*params.Params) error            { return m.initErr }
func (m *mockOperator) Close() error                         { return m.closeErr }

func (m *mockOperator) Instantiate(GadgetContext, any, *params.Params) (OperatorInstance, error) {
	if m.instErr != nil {
		return nil, m.instErr
	}
	return &mockOperatorInstance{name: m.name}, nil
}

type mockOperatorInstance struct {
	name       string
	preRunErr  error
	postRunErr error
	enrichErr  error
}

func (m *mockOperatorInstance) Name() string          { return m.name }
func (m *mockOperatorInstance) PreGadgetRun() error   { return m.preRunErr }
func (m *mockOperatorInstance) PostGadgetRun() error  { return m.postRunErr }
func (m *mockOperatorInstance) EnrichEvent(any) error { return m.enrichErr }

func TestParamDescCollection(t *testing.T) {
	allOperators = map[string]Operator{}

	op1 := &mockOperator{name: "test-op-1"}
	op2 := &mockOperator{name: "test-op-2"}

	ops := Operators{}
	coll := ops.ParamDescCollection()
	assert.Empty(t, coll, "empty operators should return empty collection")

	ops = Operators{op1, op2}
	coll = ops.ParamDescCollection()
	assert.Len(t, coll, 2, "should return param descs for all operators")
	assert.Contains(t, coll, op1.Name())
	assert.Contains(t, coll, op2.Name())
}

func TestParamCollection(t *testing.T) {
	allOperators = map[string]Operator{}

	op1 := &mockOperator{name: "test-op-1"}
	op2 := &mockOperator{name: "test-op-2"}

	ops := Operators{}
	coll := ops.ParamCollection()
	assert.Empty(t, coll, "empty operators should return empty collection")

	ops = Operators{op1, op2}
	coll = ops.ParamCollection()
	assert.Len(t, coll, 2, "should return params for all operators")
	assert.Contains(t, coll, op1.Name())
	assert.Contains(t, coll, op2.Name())
}

func TestRegisterAndGetRaw(t *testing.T) {
	allOperators = map[string]Operator{}

	op1 := &mockOperator{name: "test-op-1"}
	op2 := &mockOperator{name: "test-op-2"}

	Register(op1)
	assert.Contains(t, allOperators, op1.Name(), "operator should be registered")

	assert.Panics(t, func() {
		Register(op1)
	}, "registering duplicate operator should panic")

	retrieved := GetRaw(op1.Name())
	assert.Equal(t, op1, retrieved, "GetRaw should return the original operator")

	retrieved = GetRaw("non-existent")
	assert.Nil(t, retrieved, "GetRaw should return nil for non-existent operator")

	Register(op2)
	assert.Contains(t, allOperators, op2.Name(), "second operator should be registered")
}

func TestGetAll(t *testing.T) {
	allOperators = map[string]Operator{}

	op1 := &mockOperator{name: "test-op-1"}
	op2 := &mockOperator{name: "test-op-2"}

	Register(op1)
	Register(op2)

	ops := GetAll()
	assert.Len(t, ops, 2, "GetAll should return all registered operators")
	assert.Contains(t, ops, &operatorWrapper{Operator: op1})
	assert.Contains(t, ops, &operatorWrapper{Operator: op2})
}

func TestGlobalParamsCollection(t *testing.T) {
	allOperators = map[string]Operator{}

	op1 := &mockOperator{name: "test-op-1"}
	op2 := &mockOperator{name: "test-op-2"}

	Register(op1)
	Register(op2)

	collection := GlobalParamsCollection()
	assert.Len(t, collection, 2, "GlobalParamsCollection should return params for all operators")
	assert.Contains(t, collection, op1.Name())
	assert.Contains(t, collection, op2.Name())
}

func TestGetOperatorsForGadget(t *testing.T) {
	allOperators = map[string]Operator{}

	op1 := &mockOperator{name: "test-op-1", canOperateOn: true}
	op2 := &mockOperator{name: "test-op-2", canOperateOn: false}

	Register(op1)
	Register(op2)

	gadgetDesc := &mockGadgetDesc{
		category:    "test",
		name:        "mock",
		description: "mock gadget for testing",
	}
	ops := GetOperatorsForGadget(gadgetDesc)

	assert.Len(t, ops, 1, "should only return operators that can operate on the gadget")
	assert.Equal(t, op1.Name(), ops[0].Name())
}

func TestOperatorsInit(t *testing.T) {
	ops := Operators{
		&mockOperator{name: "test-op-1"},
		&mockOperator{name: "test-op-2", initErr: errors.New("init error")},
	}

	paramCollection := params.Collection{
		"test-op-1": &params.Params{},
		"test-op-2": &params.Params{},
	}

	err := ops.Init(paramCollection)
	assert.Error(t, err, "Init should return error if any operator fails to initialize")
	assert.Contains(t, err.Error(), "init error")
}

func TestOperatorsClose(t *testing.T) {
	ops := Operators{
		&mockOperator{name: "test-op-1"},
		&mockOperator{name: "test-op-2", closeErr: errors.New("close error")},
	}

	ops.Close()
}

func TestOperatorInstancesPrePostGadgetRun(t *testing.T) {
	instances := OperatorInstances{
		&mockOperatorInstance{name: "inst1"},
		&mockOperatorInstance{name: "inst2"},
	}

	err := instances.PreGadgetRun()
	assert.NoError(t, err)

	err = instances.PostGadgetRun()
	assert.NoError(t, err)

	instances = OperatorInstances{
		&mockOperatorInstance{name: "inst1", preRunErr: errors.New("pre-run error")},
	}

	err = instances.PreGadgetRun()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pre-run error")
}

func TestEmptyOperatorInstancesOperations(t *testing.T) {
	instances := OperatorInstances{}

	err := instances.PreGadgetRun()
	assert.NoError(t, err)

	err = instances.PostGadgetRun()
	assert.NoError(t, err)

	err = instances.Enrich(struct{}{})
	assert.NoError(t, err)
}

func TestOperatorsInstantiate(t *testing.T) {
	tests := []struct {
		name                     string
		operators                Operators
		gadgetContext            GadgetContext
		trace                    interface{}
		perGadgetParamCollection params.Collection
		expectedInstances        int
		expectError              bool
		expectedErrorContains    string
	}{
		{
			name: "successful instantiation",
			operators: Operators{
				&mockOperator{
					name:         "test-op-1",
					canOperateOn: true,
				},
				&mockOperator{
					name:         "test-op-2",
					canOperateOn: true,
				},
			},
			gadgetContext: &mockGadgetContext{},
			trace:         struct{}{},
			perGadgetParamCollection: params.Collection{
				"test-op-1": &params.Params{},
				"test-op-2": &params.Params{},
			},
			expectedInstances: 2,
			expectError:       false,
		},
		{
			name: "instantiation with error",
			operators: Operators{
				&mockOperator{
					name:         "test-op-1",
					canOperateOn: true,
				},
				&mockOperator{
					name:         "test-op-2",
					canOperateOn: true,
					instErr:      errors.New("instantiation failed"),
				},
			},
			gadgetContext: &mockGadgetContext{},
			trace:         struct{}{},
			perGadgetParamCollection: params.Collection{
				"test-op-1": &params.Params{},
				"test-op-2": &params.Params{},
			},
			expectedInstances:     0,
			expectError:           true,
			expectedErrorContains: "instantiation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instances, err := tt.operators.Instantiate(
				tt.gadgetContext,
				tt.trace,
				tt.perGadgetParamCollection,
			)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrorContains != "" {
					assert.Contains(t, err.Error(), tt.expectedErrorContains)
				}
				assert.Nil(t, instances)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedInstances, len(instances))
				if tt.expectedInstances > 0 {
					for _, instance := range instances {
						assert.NotNil(t, instance)
					}
				}
			}
		})
	}
}

type mockGadgetContext struct{}

func (m *mockGadgetContext) ID() string                                    { return "mock-id" }
func (m *mockGadgetContext) Context() context.Context                      { return context.Background() }
func (m *mockGadgetContext) GadgetDesc() gadgets.GadgetDesc                { return nil }
func (m *mockGadgetContext) Logger() logger.Logger                         { return nil }
func (m *mockGadgetContext) Cancel()                                       {}
func (m *mockGadgetContext) SerializeGadgetInfo() (*api.GadgetInfo, error) { return nil, nil }
func (m *mockGadgetContext) ImageName() string                             { return "" }
func (m *mockGadgetContext) RegisterDataSource(t datasource.Type, n string) (datasource.DataSource, error) {
	return nil, nil
}
func (m *mockGadgetContext) GetDataSources() map[string]datasource.DataSource { return nil }
func (m *mockGadgetContext) SetVar(string, any)                               {}
func (m *mockGadgetContext) GetVar(string) (any, bool)                        { return nil, false }
func (m *mockGadgetContext) Params() []*api.Param                             { return nil }
func (m *mockGadgetContext) SetParams([]*api.Param)                           {}
func (m *mockGadgetContext) SetMetadata([]byte)                               {}
func (m *mockGadgetContext) OrasTarget() oras.ReadOnlyTarget                  { return nil }
func (m *mockGadgetContext) IsRemoteCall() bool                               { return false }

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

func Test_SortOperatorsLargeGraph(t *testing.T) {
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

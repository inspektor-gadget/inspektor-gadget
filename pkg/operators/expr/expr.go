// Copyright 2024 The Inspektor Gadget authors
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

package expr

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/vm"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name            = "expr"
	ParamExpression = "expression"
	Priority        = 9000
)

type wrap struct {
	d datasource.Data
}

func (w wrap) GetString(f datasource.FieldAccessor) string {
	d, _ := f.String(w.d)
	return d
}

func (w wrap) GetUint8(f datasource.FieldAccessor) uint8 {
	d, _ := f.Uint8(w.d)
	return d
}

func (w wrap) GetUint16(f datasource.FieldAccessor) uint16 {
	d, _ := f.Uint16(w.d)
	return d
}

func (w wrap) GetUint32(f datasource.FieldAccessor) uint32 {
	d, _ := f.Uint32(w.d)
	return d
}

func (w wrap) GetUint64(f datasource.FieldAccessor) uint64 {
	d, _ := f.Uint64(w.d)
	return d
}

func (w wrap) GetInt8(f datasource.FieldAccessor) int8 {
	d, _ := f.Int8(w.d)
	return d
}

func (w wrap) GetInt16(f datasource.FieldAccessor) int16 {
	d, _ := f.Int16(w.d)
	return d
}

func (w wrap) GetInt32(f datasource.FieldAccessor) int32 {
	d, _ := f.Int32(w.d)
	return d
}

func (w wrap) GetInt64(f datasource.FieldAccessor) int64 {
	d, _ := f.Int64(w.d)
	return d
}

func (w wrap) GetFloat32(f datasource.FieldAccessor) float32 {
	d, _ := f.Float32(w.d)
	return d
}

func (w wrap) GetFloat64(f datasource.FieldAccessor) float64 {
	d, _ := f.Float64(w.d)
	return d
}

func (w wrap) GetBool(f datasource.FieldAccessor) bool {
	d, _ := f.Bool(w.d)
	return d
}

func getFnAndReflectType(f datasource.FieldAccessor) (string, reflect.Type) {
	switch f.Type() {
	case api.Kind_CString, api.Kind_String:
		return "GetString", reflect.TypeOf("")
	case api.Kind_Uint8:
		return "GetUint8", reflect.TypeOf(uint8(0))
	case api.Kind_Uint16:
		return "GetUint16", reflect.TypeOf(uint16(0))
	case api.Kind_Uint32:
		return "GetUint32", reflect.TypeOf(uint32(0))
	case api.Kind_Uint64:
		return "GetUint64", reflect.TypeOf(uint64(0))
	case api.Kind_Int8:
		return "GetInt8", reflect.TypeOf(int8(0))
	case api.Kind_Int16:
		return "GetInt16", reflect.TypeOf(int16(0))
	case api.Kind_Int32:
		return "GetInt32", reflect.TypeOf(int32(0))
	case api.Kind_Int64:
		return "GetInt64", reflect.TypeOf(int64(0))
	case api.Kind_Float32:
		return "GetFloat32", reflect.TypeOf(float32(0))
	case api.Kind_Float64:
		return "GetFloat64", reflect.TypeOf(float64(0))
	case api.Kind_Bool:
		return "GetBool", reflect.TypeOf(false)
	}
	return "", nil
}

func replaceNode(node *ast.Node, f datasource.FieldAccessor) {
	if f == nil {
		return
	}

	// if target contains subfields, return the fieldAccessor itself
	if len(f.SubFields()) > 0 {
		constNode := &ast.ConstantNode{Value: f}
		ast.Patch(node, constNode)
		(*node).SetType(reflect.TypeOf(f))
		return
	}

	// otherwise return value
	fn, ft := getFnAndReflectType(f)
	if fn == "" {
		return
	}

	callNode := &ast.CallNode{
		Callee:    &ast.IdentifierNode{Value: fn},
		Arguments: []ast.Node{&ast.ConstantNode{Value: f}},
	}
	ast.Patch(node, callNode)
	(*node).SetType(ft)
}

type dsWrap struct {
	ds datasource.DataSource
}

type dsPatcher struct {
	ds datasource.DataSource
}

func (dsp dsPatcher) Visit(node *ast.Node) {
	if nx, ok := (*node).(*ast.MemberNode); ok {
		cn, ok := nx.Node.(*ast.ConstantNode)
		if !ok {
			return
		}
		pn, ok := nx.Property.(*ast.StringNode)
		if !ok {
			return
		}

		rf, ok := cn.Value.(datasource.FieldAccessor)
		if !ok {
			return
		}
		var f datasource.FieldAccessor
		for _, sf := range rf.SubFields() {
			if sf.Name() == pn.Value {
				f = sf
				break
			}
		}
		replaceNode(node, f)
		return
	}
	if nx, ok := (*node).(*ast.IdentifierNode); ok {
		f := dsp.ds.GetField(nx.Value)
		if f == nil {
			return
		}

		replaceNode(node, f)
		return
	}
}

type expressionOperator struct{}

func (f *expressionOperator) Name() string {
	return name
}

func (f *expressionOperator) Init(params *params.Params) error {
	return nil
}

func (f *expressionOperator) GlobalParams() api.Params {
	return nil
}

func (f *expressionOperator) InstanceParams() api.Params {
	return api.Params{&api.Param{
		Key:         ParamExpression,
		Description: `comparison expression`,
		Alias:       "E",
	}}
}

func (f *expressionOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	expressionCfg, _ := instanceParamValues[ParamExpression]
	dataSources := gadgetCtx.GetDataSources()

	dsMap := make(map[datasource.DataSource]*vm.Program)

	for _, fullExpression := range strings.Split(expressionCfg, ",") {
		expressionInfo := strings.SplitN(fullExpression, ":", 2)
		var dsName string
		expression := expressionInfo[0]
		if len(expressionInfo) == 2 {
			dsName = expressionInfo[0]
			expression = expressionInfo[1]
		}

		if dsName != "" {
			ds, ok := dataSources[dsName]
			if !ok {
				return nil, fmt.Errorf("datasource not found: %q", dsName)
			}

			if _, ok := dsMap[ds]; ok {
				return nil, fmt.Errorf("more than one filter for datasource %q defined", dsName)
			}

			dsp := dsPatcher{
				ds: ds,
			}
			prog, err := expr.Compile(expression, expr.AsBool(), expr.Patch(dsp), expr.Env(&wrap{}))
			if err != nil {
				return nil, fmt.Errorf("failed to compile expression: %w", err)
			}

			dsMap[ds] = prog
		}
	}

	return &expressionOperatorInstance{dsMap: dsMap}, nil
}

func (f *expressionOperator) Priority() int {
	return Priority
}

type expressionOperatorInstance struct {
	dsMap map[datasource.DataSource]*vm.Program
}

func (f *expressionOperatorInstance) Name() string {
	return name
}

func (f *expressionOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, prog := range f.dsMap {
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			res, err := expr.Run(prog, wrap{d: data})
			if err != nil {
				return fmt.Errorf("failed to evaluate expression: %w", err)
			}
			if b, ok := res.(bool); ok && !b {
				return datasource.ErrDiscard
			}
			return nil
		}, Priority) // TODO: need some predefined & sane values
	}
	return nil
}

func (f *expressionOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (f *expressionOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.RegisterDataOperator(&expressionOperator{})
}

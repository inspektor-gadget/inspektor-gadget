// Copyright 2024-2025 The Inspektor Gadget authors
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

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/vm"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type dsPatcher struct {
	ds datasource.DataSource
}

func (dsp dsPatcher) Visit(node *ast.Node) {
	switch nx := (*node).(type) {
	case *ast.MemberNode:
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
	case *ast.IdentifierNode:
		f := dsp.ds.GetField(nx.Value)
		replaceNode(node, f)
	}
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
		Arguments: []ast.Node{&ast.ConstantNode{Value: f}, &ast.IdentifierNode{Value: "$env"}},
	}
	ast.Patch(node, callNode)
	(*node).SetType(ft)
}

func getFnAndReflectType(f datasource.FieldAccessor) (string, reflect.Type) {
	switch f.Type() {
	default:
		fallthrough // anything can be read as string
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
}

func getBuiltInExpressions() []expr.Option {
	return []expr.Option{
		expr.Function("GetString",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).String(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) string),
		),
		expr.Function("GetUint8",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Uint8(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) uint8),
		),
		expr.Function("GetUint16",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Uint16(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) uint16),
		),
		expr.Function("GetUint32",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Uint32(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) uint32),
		),
		expr.Function("GetUint64",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Uint64(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) uint64),
		),
		expr.Function("GetInt8",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Int8(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) int8),
		),
		expr.Function("GetInt16",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Int16(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) int16),
		),
		expr.Function("GetInt32",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Int32(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) int32),
		),
		expr.Function("GetInt64",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Int64(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) int64),
		),
		expr.Function("GetFloat32",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Float32(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) float32),
		),
		expr.Function("GetFloat64",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Float64(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) float64),
		),
		expr.Function("GetBool",
			func(params ...any) (any, error) {
				return params[0].(datasource.FieldAccessor).Bool(params[1].(datasource.Data))
			},
			new(func(datasource.FieldAccessor, datasource.Data) bool),
		),
	}
}

func CompileStringProgram(ds datasource.DataSource, expression string) (*vm.Program, error) {
	dsp := dsPatcher{
		ds: ds,
	}

	options := append(getBuiltInExpressions(), expr.AsKind(reflect.String), expr.Patch(dsp))

	prog, err := expr.Compile(expression, options...)
	if err != nil {
		return nil, fmt.Errorf("compiling string expression: %w", err)
	}
	return prog, nil
}

func CompileFilterProgram(ds datasource.DataSource, expression string) (*vm.Program, error) {
	dsp := dsPatcher{
		ds: ds,
	}

	options := append(getBuiltInExpressions(), expr.AsBool(), expr.Patch(dsp), expr.Env(datasource.Data(nil)))

	prog, err := expr.Compile(expression, options...)
	if err != nil {
		return nil, fmt.Errorf("compiling filter expression: %w", err)
	}
	return prog, nil
}

func Run(program *vm.Program, data datasource.Data) (any, error) {
	return expr.Run(program, data)
}

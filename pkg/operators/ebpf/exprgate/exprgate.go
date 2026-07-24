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

// Package exprgate provides a small, namespaced expression evaluator used to
// gate eBPF objects declaratively via btf_decl_tag annotations (GADGET_MAP_ONLY_IF,
// GADGET_PROG_ATTACH_TO, GADGET_ASSERT, GADGET_EXPR_DEFINE).
//
// Expressions are written in expr-lang (github.com/expr-lang/expr) and evaluated
// over a namespaced environment:
//
//   - params.<name>    resolved GADGET_PARAM values
//   - kallsyms.exists(s) / kallsyms.first(...)
//   - program.disabled the sentinel returned to skip a program
//   - <define>         values produced by GADGET_EXPR_DEFINE
//
// Which namespaces are visible depends on the expression Kind (see the Kind
// constants). Expressions are compiled at analyze time (so typos and type
// errors are caught early) and evaluated once, before load, in a single
// pre-start pass.
package exprgate

import (
	"fmt"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// ProgramDisabled is the sentinel value an attach_to expression returns to
// disable (skip attaching) a program. It matches the disabledProgram constant
// consumed by the attach path.
const ProgramDisabled = "gadget_program_disabled"

// Kind selects the environment shape and the expected result type of an
// expression.
type Kind int

const (
	// KindOnlyIf is a GADGET_MAP_ONLY_IF expression. Env: params.* and defines.
	// Must return bool. kallsyms.* is deliberately NOT exposed (a map gate must
	// track the const-volatile param guarding its C users, never kallsyms).
	KindOnlyIf Kind = iota
	// KindAttachTo is a GADGET_PROG_ATTACH_TO expression. Env: params.*,
	// kallsyms.*, program.disabled and defines. Must return string.
	KindAttachTo
	// KindAssert is a GADGET_ASSERT expression. Env: params.*, kallsyms.* and
	// defines. Must return bool.
	KindAssert
	// KindDefine is a GADGET_EXPR_DEFINE expression. Env: params.*, kallsyms.*,
	// program.disabled and earlier defines. May return any type.
	KindDefine
)

func (k Kind) String() string {
	switch k {
	case KindOnlyIf:
		return "only_if"
	case KindAttachTo:
		return "attach_to"
	case KindAssert:
		return "assert"
	case KindDefine:
		return "define"
	default:
		return fmt.Sprintf("Kind(%d)", int(k))
	}
}

func (k Kind) usesKallsyms() bool { return k != KindOnlyIf }
func (k Kind) usesProgram() bool  { return k == KindAttachTo || k == KindDefine }

// kallsymsNS is the kallsyms.* namespace. The expr struct tags expose the
// methods with lowercase names.
type kallsymsNS struct {
	Exists func(string) bool               `expr:"exists"`
	First  func(...string) (string, error) `expr:"first"`
}

// programNS is the program.* namespace.
type programNS struct {
	Disabled string `expr:"disabled"`
}

// KallsymsFuncs supplies the implementations backing kallsyms.exists/first.
// It is injected so tests can stub kernel symbol lookups.
type KallsymsFuncs struct {
	Exists func(symbol string) bool
	First  func(symbols ...string) (string, error)
}

var interfaceType = reflect.TypeOf((*any)(nil)).Elem()

// Program is a compiled expression together with the metadata needed to build
// the evaluation environment.
type Program struct {
	src      string
	kind     Kind
	prog     *vm.Program
	envType  reflect.Type
	fieldIdx map[string]int // env member name -> struct field index
	defines  []string       // define names visible to this program
}

// Src returns the original expression text.
func (p *Program) Src() string { return p.src }

// Kind returns the expression kind.
func (p *Program) Kind() Kind { return p.kind }

// Evaluator compiles and evaluates the ig: expressions of a single gadget. It
// must be created with the full, ordered list of GADGET_EXPR_DEFINE names so
// that define visibility (a define only sees earlier defines) can be enforced
// at compile time.
type Evaluator struct {
	defineOrder []string
	defineIndex map[string]int
	kallsyms    KallsymsFuncs
}

// New creates an Evaluator. defineOrder is the list of define names in source
// (BTF declaration) order. kallsyms provides the kallsyms.* implementations;
// if a function is nil a no-op default is used.
func New(defineOrder []string, kallsyms KallsymsFuncs) *Evaluator {
	idx := make(map[string]int, len(defineOrder))
	for i, name := range defineOrder {
		idx[name] = i
	}
	if kallsyms.Exists == nil {
		kallsyms.Exists = func(string) bool { return false }
	}
	if kallsyms.First == nil {
		kallsyms.First = func(...string) (string, error) { return "", fmt.Errorf("kallsyms.first not available") }
	}
	return &Evaluator{
		defineOrder: defineOrder,
		defineIndex: idx,
		kallsyms:    kallsyms,
	}
}

// buildEnvType builds the reflect struct type of the environment for the given
// kind and set of visible defines, returning the type and a name->field-index
// map. params is always a map[string]any field; kallsyms/program are typed
// structs (present only when the kind allows); each visible define is an
// interface{} field so define-derived values are treated as dynamic (any).
func buildEnvType(kind Kind, visibleDefines []string) (reflect.Type, map[string]int) {
	fields := make([]reflect.StructField, 0, 3+len(visibleDefines))
	fieldIdx := make(map[string]int, 3+len(visibleDefines))

	add := func(member string, typ reflect.Type) {
		fieldIdx[member] = len(fields)
		fields = append(fields, reflect.StructField{
			Name: fmt.Sprintf("F%d", len(fields)),
			Type: typ,
			Tag:  reflect.StructTag(fmt.Sprintf("expr:%q", member)),
		})
	}

	add("params", reflect.TypeOf(map[string]any(nil)))
	if kind.usesKallsyms() {
		add("kallsyms", reflect.TypeOf(kallsymsNS{}))
	}
	if kind.usesProgram() {
		add("program", reflect.TypeOf(programNS{}))
	}
	for _, d := range visibleDefines {
		add(d, interfaceType)
	}

	return reflect.StructOf(fields), fieldIdx
}

// visibleDefinesFor returns the define names visible to an expression. For a
// define, only earlier defines are visible (defineName is the define being
// compiled); for any other expression, all defines are visible.
func (e *Evaluator) visibleDefinesFor(kind Kind, defineName string) []string {
	if kind == KindDefine {
		i, ok := e.defineIndex[defineName]
		if !ok {
			return nil
		}
		return e.defineOrder[:i]
	}
	return e.defineOrder
}

// Compile compiles exprStr for the given kind. For KindDefine, defineName must
// be the name of the define being compiled (so it only sees earlier defines);
// for all other kinds defineName is ignored.
func (e *Evaluator) Compile(exprStr string, kind Kind, defineName string) (*Program, error) {
	visible := e.visibleDefinesFor(kind, defineName)
	envType, fieldIdx := buildEnvType(kind, visible)
	zeroEnv := reflect.New(envType).Elem().Interface()

	opts := []expr.Option{expr.Env(zeroEnv)}
	switch kind {
	case KindOnlyIf, KindAssert:
		opts = append(opts, expr.AsBool())
	case KindAttachTo:
		opts = append(opts, expr.AsKind(reflect.String))
	case KindDefine:
		// no result-type constraint
	}

	prog, err := expr.Compile(exprStr, opts...)
	if err != nil {
		return nil, fmt.Errorf("compiling %s expression %q: %w", kind, exprStr, err)
	}
	return &Program{
		src:      exprStr,
		kind:     kind,
		prog:     prog,
		envType:  envType,
		fieldIdx: fieldIdx,
		defines:  visible,
	}, nil
}

// buildEnvValue constructs a populated environment value for p from the given
// resolved params and already-evaluated defines.
func (e *Evaluator) buildEnvValue(p *Program, params map[string]any, defines map[string]any) (any, error) {
	v := reflect.New(p.envType).Elem()

	v.Field(p.fieldIdx["params"]).Set(reflect.ValueOf(params))
	if idx, ok := p.fieldIdx["kallsyms"]; ok {
		v.Field(idx).Set(reflect.ValueOf(kallsymsNS{
			Exists: e.kallsyms.Exists,
			First:  e.kallsyms.First,
		}))
	}
	if idx, ok := p.fieldIdx["program"]; ok {
		v.Field(idx).Set(reflect.ValueOf(programNS{Disabled: ProgramDisabled}))
	}
	for _, d := range p.defines {
		val, ok := defines[d]
		if !ok {
			return nil, fmt.Errorf("internal error: define %q not evaluated before use", d)
		}
		field := v.Field(p.fieldIdx[d])
		if val != nil {
			field.Set(reflect.ValueOf(val))
		}
	}
	return v.Interface(), nil
}

// run evaluates p against the given params and defines and returns the raw
// result.
func (e *Evaluator) run(p *Program, params map[string]any, defines map[string]any) (any, error) {
	env, err := e.buildEnvValue(p, params, defines)
	if err != nil {
		return nil, err
	}
	out, err := expr.Run(p.prog, env)
	if err != nil {
		return nil, fmt.Errorf("evaluating %s expression %q: %w", p.kind, p.src, err)
	}
	return out, nil
}

// EvalBool evaluates a bool-returning expression (only_if / assert).
func (e *Evaluator) EvalBool(p *Program, params map[string]any, defines map[string]any) (bool, error) {
	out, err := e.run(p, params, defines)
	if err != nil {
		return false, err
	}
	b, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("%s expression %q must return bool, got %T", p.kind, p.src, out)
	}
	return b, nil
}

// EvalString evaluates a string-returning expression (attach_to).
func (e *Evaluator) EvalString(p *Program, params map[string]any, defines map[string]any) (string, error) {
	out, err := e.run(p, params, defines)
	if err != nil {
		return "", err
	}
	if out == nil {
		return "", fmt.Errorf("%s expression %q returned nil (is the indexed key present?)", p.kind, p.src)
	}
	s, ok := out.(string)
	if !ok {
		return "", fmt.Errorf("%s expression %q must return string, got %T", p.kind, p.src, out)
	}
	return s, nil
}

// EvalAny evaluates a define expression, returning its raw value.
func (e *Evaluator) EvalAny(p *Program, params map[string]any, defines map[string]any) (any, error) {
	return e.run(p, params, defines)
}

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
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/exprgate"
)

// All IG decl tags are prefixed with "ig:" to avoid clashing with third-party
// btf_decl_tag attributes.
const igTagPrefix = "ig:"

// ig: decl-tag kinds.
const (
	igTagOnlyIf        = "only_if"         // GADGET_MAP_ONLY_IF (on a map)
	igTagAttachTo      = "attach_to"       // GADGET_PROG_ATTACH_TO (on a program func)
	igTagAssert        = "assert"          // GADGET_ASSERT (on a throwaway var)
	igTagDefine        = "define"          // GADGET_EXPR_DEFINE (on a throwaway var)
	igTagParam         = "param"           // GADGET_PARAM (on a throwaway var)
	igTagMapIter       = "mapiter"         // GADGET_MAPITER (on a throwaway var)
	igTagIterTargetMap = "iter_target_map" // GADGET_ITER_TARGET_MAP (on a throwaway var)
)

// exprBinding is a named, compiled expression (used for defines and asserts).
type exprBinding struct {
	name string
	prog *exprgate.Program
}

// parseIGTag splits an "ig:<kind>[:<value>]" decl tag into its kind and value.
// The value is the remainder after the second ':' and may itself contain ':'
// (e.g. an expr like "a ? 'x' : 'y'"). It returns ok=false for non-ig tags.
func parseIGTag(tag string) (kind, value string, ok bool) {
	if !strings.HasPrefix(tag, igTagPrefix) {
		return "", "", false
	}
	rest := tag[len(igTagPrefix):]
	if idx := strings.IndexByte(rest, ':'); idx >= 0 {
		return rest[:idx], rest[idx+1:], true
	}
	return rest, "", true
}

// splitNameExpr splits a "<name>:<expr>" value (used by ig:define and
// ig:assert). <name> is identifier-safe so splitting on the first ':' is safe.
func splitNameExpr(value string) (name, expr string, ok bool) {
	idx := strings.IndexByte(value, ':')
	if idx < 0 {
		return "", "", false
	}
	return value[:idx], value[idx+1:], true
}

// readExprTags reads the ig: decl tags that carry expressions
// (GADGET_MAP_ONLY_IF, GADGET_PROG_ATTACH_TO, GADGET_ASSERT,
// GADGET_EXPR_DEFINE), compiles them and records the bindings. It is called
// from analyze() after the legacy prefix walk. The behaviors driven by these
// bindings (map gating, program attach, asserts, define evaluation) are wired
// up separately, in the pre-start pass.
func (i *ebpfInstance) readExprTags(gadgetCtx operators.GadgetContext) error {
	// First pass: collect raw (uncompiled) tag values. Defines and asserts
	// live on throwaway variables and must be gathered in BTF declaration
	// order (Spec.All iterates in ascending type-ID order).
	type rawBinding struct{ name, expr string }
	var (
		rawDefines   []rawBinding
		rawAsserts   []rawBinding
		rawOnlyIf    = map[string]string{} // map name -> expr
		rawAttachTo  = map[string]string{} // program name -> expr
		definesOrder []string
	)

	for typ, err := range i.collectionSpec.Types.All() {
		if err != nil {
			return fmt.Errorf("iterating over types: %w", err)
		}
		v, ok := typ.(*btf.Var)
		if !ok {
			continue
		}
		for _, tag := range v.Tags {
			kind, value, ok := parseIGTag(tag)
			if !ok {
				continue
			}
			switch kind {
			case igTagDefine, igTagAssert:
				name, expr, ok := splitNameExpr(value)
				if !ok {
					return fmt.Errorf("malformed ig:%s tag %q on %q: expected <name>:<expr>", kind, tag, v.Name)
				}
				if kind == igTagDefine {
					rawDefines = append(rawDefines, rawBinding{name, expr})
					definesOrder = append(definesOrder, name)
				} else {
					rawAsserts = append(rawAsserts, rawBinding{name, expr})
				}
			}
		}
	}

	// Maps: GADGET_MAP_ONLY_IF.
	for name, ms := range i.collectionSpec.Maps {
		for _, tag := range ms.Tags {
			kind, value, ok := parseIGTag(tag)
			if !ok {
				continue
			}
			if kind == igTagOnlyIf {
				rawOnlyIf[name] = value
			}
		}
	}

	// Programs: GADGET_PROG_ATTACH_TO. The btf.Func carrying the tags is
	// attached to the program's first instruction.
	for name, p := range i.collectionSpec.Programs {
		if len(p.Instructions) == 0 {
			continue
		}
		fn := btf.FuncMetadata(&p.Instructions[0])
		if fn == nil {
			continue
		}
		for _, tag := range fn.Tags {
			kind, value, ok := parseIGTag(tag)
			if !ok {
				continue
			}
			if kind == igTagAttachTo {
				rawAttachTo[name] = value
			}
		}
	}

	// Nothing to do if the gadget uses no expr tags.
	if len(rawDefines) == 0 && len(rawAsserts) == 0 && len(rawOnlyIf) == 0 && len(rawAttachTo) == 0 {
		return nil
	}

	// Second pass: build the evaluator (it needs the full ordered define list)
	// and compile every expression, so typos and type errors surface now, at
	// analyze time.
	i.exprEval = exprgate.New(definesOrder, exprgate.KallsymsFuncs{
		Exists: kallsyms.SymbolExists,
		First:  kallsymsFirst,
	})

	seenDefine := map[string]bool{}
	for _, d := range rawDefines {
		if seenDefine[d.name] {
			return fmt.Errorf("duplicate GADGET_EXPR_DEFINE %q", d.name)
		}
		seenDefine[d.name] = true
		prog, err := i.exprEval.Compile(d.expr, exprgate.KindDefine, d.name)
		if err != nil {
			return fmt.Errorf("GADGET_EXPR_DEFINE %q: %w", d.name, err)
		}
		i.exprDefines = append(i.exprDefines, exprBinding{name: d.name, prog: prog})
	}

	for _, a := range rawAsserts {
		prog, err := i.exprEval.Compile(a.expr, exprgate.KindAssert, "")
		if err != nil {
			return fmt.Errorf("GADGET_ASSERT %q: %w", a.name, err)
		}
		i.exprAsserts = append(i.exprAsserts, exprBinding{name: a.name, prog: prog})
	}

	for name, expr := range rawOnlyIf {
		prog, err := i.exprEval.Compile(expr, exprgate.KindOnlyIf, "")
		if err != nil {
			return fmt.Errorf("GADGET_MAP_ONLY_IF on map %q: %w", name, err)
		}
		i.mapOnlyIf[name] = prog
		i.logger.Debugf("map %q gated by only_if %q", name, expr)
	}

	for name, expr := range rawAttachTo {
		prog, err := i.exprEval.Compile(expr, exprgate.KindAttachTo, "")
		if err != nil {
			return fmt.Errorf("GADGET_PROG_ATTACH_TO on program %q: %w", name, err)
		}
		i.progAttachTo[name] = prog
		i.logger.Debugf("program %q attach_to %q", name, expr)
	}

	return nil
}

// kallsymsFirst returns the first of the given symbols that exists in the
// kernel, or an error naming all candidates if none exists.
func kallsymsFirst(symbols ...string) (string, error) {
	for _, s := range symbols {
		if kallsyms.SymbolExists(s) {
			return s, nil
		}
	}
	return "", fmt.Errorf("none of the candidate kernel symbols exist: %s", strings.Join(symbols, ", "))
}

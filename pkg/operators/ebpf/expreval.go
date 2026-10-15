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
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// gatedMapHint returns a human-readable note listing the maps that were gated
// off by GADGET_MAP_ONLY_IF, to be appended to a load/verifier error: a
// still-live reference to a gated-off map is a likely cause. It returns "" when
// no maps were gated (so unrelated errors are not decorated).
func (i *ebpfInstance) gatedMapHint(err error) string {
	if len(i.gatedMaps) == 0 {
		return ""
	}
	var verifierErr *ebpf.VerifierError
	if !errors.As(err, &verifierErr) {
		return ""
	}
	hint := "note: the following maps were not created because their GADGET_MAP_ONLY_IF condition was false;\n" +
		"if the verifier error above is a rejected map access, that code is still reachable and must be\n" +
		"guarded by the same condition:"
	for _, gm := range i.gatedMaps {
		hint += fmt.Sprintf("\n  - map %q gated by GADGET_MAP_ONLY_IF(%q)", gm.name, gm.expr)
	}
	return hint
}

// poisonSentinel is loaded into R10 (the read-only frame pointer) in place of a
// map-load instruction whose map was gated off. Writing R10 is illegal, so the
// verifier rejects it iff the instruction is reached (i.e. the referencing code
// was not actually dead) — the intended loud author-error failure. If the code
// is dead, the verifier prunes it and the load succeeds with the map skipped.
const poisonSentinel = 0x0badca11

// gatedMap records a map that GADGET_MAP_ONLY_IF dropped, so a verifier error
// can hint that a still-live reference to it is the likely cause.
type gatedMap struct {
	name string
	expr string
}

// evaluateExprTags runs the single pre-start pass that evaluates the compiled
// ig: decl-tag expressions. It must run after params are resolved into the
// spec and before the collection is loaded.
func (i *ebpfInstance) evaluateExprTags(gadgetCtx operators.GadgetContext, paramMap map[string]*params.Param) error {
	if i.exprEval == nil {
		return nil
	}

	exprParams := i.buildExprParams(paramMap)

	defines, err := i.evaluateDefines(exprParams)
	if err != nil {
		return err
	}

	if err := i.evaluateAsserts(exprParams, defines); err != nil {
		return err
	}

	if err := i.evaluateAttachTo(exprParams, defines); err != nil {
		return err
	}

	if err := i.gateMaps(gadgetCtx, exprParams, defines); err != nil {
		return err
	}

	return nil
}

// evaluateAttachTo evaluates GADGET_PROG_ATTACH_TO for every tagged program and
// records the resulting symbol as the programs.<name>.attach_to config value,
// which attachProgram already consults. An explicit config value (e.g. a user
// override or gadget.yaml setting) takes precedence and is never clobbered. The
// expression may evaluate to the sentinel that disables the program.
func (i *ebpfInstance) evaluateAttachTo(exprParams, defines map[string]any) error {
	for progName, prog := range i.progAttachTo {
		key := "programs." + progName + ".attach_to"
		if i.config != nil && i.config.IsSet(key) {
			i.logger.Debugf("program %q attach_to already set to %q; not overriding with expr",
				progName, i.config.GetString(key))
			continue
		}
		sym, err := i.exprEval.EvalString(prog, exprParams, defines)
		if err != nil {
			return fmt.Errorf("GADGET_PROG_ATTACH_TO on program %q: %w", progName, err)
		}
		i.logger.Debugf("program %q attach_to resolved to %q (from %q)", progName, sym, prog.Src())
		if i.config != nil {
			i.config.Set(key, sym)
		}
	}
	return nil
}

// evaluateAsserts evaluates every GADGET_ASSERT precondition. All failing
// asserts are aggregated into a single error so the author sees every unmet
// requirement at once rather than fixing them one at a time.
func (i *ebpfInstance) evaluateAsserts(exprParams, defines map[string]any) error {
	var failures []string
	for _, a := range i.exprAsserts {
		ok, err := i.exprEval.EvalBool(a.prog, exprParams, defines)
		if err != nil {
			return fmt.Errorf("GADGET_ASSERT %q: %w", a.name, err)
		}
		if !ok {
			failures = append(failures, fmt.Sprintf("%s (%s)", a.name, a.prog.Src()))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("GADGET_ASSERT precondition(s) failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

// evaluateDefines evaluates every GADGET_EXPR_DEFINE in source order,
// accumulating each result into the defines environment so that a later define
// can reference an earlier one. The resulting map is shared as the defines
// environment for map gating, asserts and attach_to.
func (i *ebpfInstance) evaluateDefines(exprParams map[string]any) (map[string]any, error) {
	defines := make(map[string]any, len(i.exprDefines))
	for _, d := range i.exprDefines {
		val, err := i.exprEval.EvalAny(d.prog, exprParams, defines)
		if err != nil {
			return nil, fmt.Errorf("GADGET_EXPR_DEFINE %q: %w", d.name, err)
		}
		defines[d.name] = val
		i.logger.Debugf("define %q = %v (from %q)", d.name, val, d.prog.Src())
	}
	return defines, nil
}

// buildExprParams builds the params.* environment from the resolved parameter
// values. Numeric params are normalized to int64/uint64/float64 so expressions
// compare consistently across widths (and a signed sentinel like -1 keeps its
// value).
func (i *ebpfInstance) buildExprParams(paramMap map[string]*params.Param) map[string]any {
	env := make(map[string]any, len(i.params))
	for name := range i.params {
		p := paramMap[name]
		if p == nil {
			continue
		}
		env[name] = normalizeParamValue(p)
	}
	return env
}

func normalizeParamValue(p *params.Param) any {
	switch p.TypeHint {
	case params.TypeBool:
		return p.AsBool()
	case params.TypeString, params.TypeBytes:
		return p.AsString()
	case params.TypeInt, params.TypeInt8, params.TypeInt16, params.TypeInt32,
		params.TypeInt64, params.TypeDuration:
		return p.AsInt64()
	case params.TypeUint, params.TypeUint8, params.TypeUint16, params.TypeUint32,
		params.TypeUint64:
		return p.AsUint64()
	case params.TypeFloat32, params.TypeFloat64:
		return p.AsFloat64()
	default:
		return p.AsString()
	}
}

// gateMaps evaluates GADGET_MAP_ONLY_IF for every tagged map. When the
// expression is false the map's references are poisoned in every program and
// the map is dropped from the spec, so the collection loads without allocating
// the map (provided its C users are dead code).
func (i *ebpfInstance) gateMaps(gadgetCtx operators.GadgetContext, exprParams, defines map[string]any) error {
	for mapName, prog := range i.mapOnlyIf {
		required, err := i.exprEval.EvalBool(prog, exprParams, defines)
		if err != nil {
			return fmt.Errorf("map %q: %w", mapName, err)
		}
		if required {
			i.logger.Debugf("map %q kept (only_if %q is true)", mapName, prog.Src())
			continue
		}

		n := i.poisonMapReferences(mapName)
		i.logger.Debugf("map %q gated off by only_if %q; poisoned %d reference(s) and dropped it",
			mapName, prog.Src(), n)
		delete(i.collectionSpec.Maps, mapName)
		i.gatedMaps = append(i.gatedMaps, gatedMap{name: mapName, expr: prog.Src()})
	}
	return nil
}

// poisonMapReferences replaces every map-load instruction referencing mapName,
// across all programs, with a size-preserving illegal load into R10 (see
// poisonSentinel). Instruction metadata (BTF source/line info) is preserved so
// that a verifier error still points at the original source line. It returns
// the number of poisoned instructions.
func (i *ebpfInstance) poisonMapReferences(mapName string) int {
	count := 0
	for _, p := range i.collectionSpec.Programs {
		for idx := range p.Instructions {
			ins := &p.Instructions[idx]
			if ins.IsLoadFromMap() && ins.Reference() == mapName {
				*ins = asm.LoadImm(asm.R10, poisonSentinel, asm.DWord).WithMetadata(ins.Metadata)
				count++
			}
		}
	}
	return count
}

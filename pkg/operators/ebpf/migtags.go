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
	"sort"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// readMigratedDeclTags reads the ig: decl tags that are the new encoding of the
// legacy name-encoded magic globals (GADGET_PARAM -> ig:param, GADGET_MAPITER ->
// ig:mapiter, GADGET_ITER_TARGET_MAP -> ig:iter_target_map, GADGET_TRACER ->
// ig:tracer, GADGET_ITER -> ig:iter / ig:iter_type, GADGET_TRACER_MAP ->
// ig:tracer_map, gadget_var_ -> ig:var). It runs in analyze(), before
// fillParamDefaults(), alongside — not instead of — the legacy prefix walk (see
// pkg/operators/ebpf/types.go): a gadget built with the new macros carries ig:
// tags, while a pre-built old image carries only the gadget_*___* symbols. Both
// are supported permanently; the populate* helpers (and the guards here) are
// idempotent, so an object carrying both encodings is handled once.
//
// GADGET_PF is intentionally not read here: packet filters are discovered by
// scanning instruction symbols for the gadget_pf_ prefix (see analyze()), so its
// ig:packetfilter tag is additive discovery metadata with no behavior-changing
// reader.
func (i *ebpfInstance) readMigratedDeclTags(gadgetCtx operators.GadgetContext) error {
	// iterTypes maps an iterator name to its element struct name (from the
	// ig:iter_type phantom); iterProgs maps an iterator name to its member
	// program functions (from ig:iter tags on the funcs). Both are gathered
	// first, then combined into populateIterators calls.
	iterTypes := map[string]string{}
	iterProgs := map[string][]string{}

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
			case igTagParam:
				// value is the name of the const volatile variable the
				// GADGET_PARAM macro was invoked with.
				if err := i.populateParam(nil, value); err != nil {
					return fmt.Errorf("handling ig:param %q: %w", value, err)
				}
			case igTagMapIter:
				// value is "<name>___<mapname>"; populateMapIter splits it
				// on typeSplitter. Skip if already registered by the legacy
				// gadget_mapiter_ walk (old image carrying both encodings).
				if name, _, ok := strings.Cut(value, typeSplitter); ok {
					if _, dup := i.mapIters[name]; dup {
						continue
					}
				}
				if err := i.populateMapIter(nil, value); err != nil {
					return fmt.Errorf("handling ig:mapiter %q: %w", value, err)
				}
			case igTagIterTargetMap:
				// value is "<prog_name>___<mapname>"; populateIterTargetMap
				// splits it on typeSplitter. Skip if already registered by the
				// legacy gadget_mapelem_iter_target_ walk.
				if prog, _, ok := strings.Cut(value, typeSplitter); ok {
					if _, dup := i.iterTargetMaps[prog]; dup {
						continue
					}
				}
				if err := i.populateIterTargetMap(nil, value); err != nil {
					return fmt.Errorf("handling ig:iter_target_map %q: %w", value, err)
				}
			case igTagTracer:
				// value is "<name>___<map>___<event_type>"; populateTracer
				// splits it on typeSplitter. Skip if the legacy gadget_tracer_
				// walk already registered it.
				if name, _, ok := strings.Cut(value, typeSplitter); ok {
					if _, dup := i.tracers[name]; dup {
						continue
					}
				}
				if err := i.populateTracer(nil, value); err != nil {
					return fmt.Errorf("handling ig:tracer %q: %w", value, err)
				}
			case igTagIterType:
				// value is "<name>___<struct>". Record the element type; the
				// program list is gathered from the func tags below.
				name, structName, ok := strings.Cut(value, typeSplitter)
				if !ok {
					return fmt.Errorf("malformed ig:iter_type %q: expected <name>___<struct>", value)
				}
				iterTypes[name] = structName
			case igTagVar:
				// The ig:var tag sits on the real const volatile variable, so
				// populateVar receives the actual btf.Var (unlike the encodings
				// above, which use throwaway vars). Skip if the legacy
				// gadget_var_ walk already registered it.
				if _, dup := i.vars[v.Name]; dup {
					continue
				}
				if err := i.populateVar(v, v.Name); err != nil {
					return fmt.Errorf("handling ig:var %q: %w", v.Name, err)
				}
			}
		}
	}

	// Maps: GADGET_TRACER_MAP tags its ring buffer map with ig:tracer_map so IG
	// can downgrade it to a perf event array when BPF ring buffers are
	// unavailable. fixTracerMap is idempotent, so an old image carrying both the
	// legacy gadget_map_tracer_ throwaway and the tag is handled correctly.
	for mapName, ms := range i.collectionSpec.Maps {
		for _, tag := range ms.Tags {
			kind, _, ok := parseIGTag(tag)
			if !ok || kind != igTagTracerMap {
				continue
			}
			if err := i.fixTracerMap(nil, mapName); err != nil {
				return fmt.Errorf("handling ig:tracer_map %q: %w", mapName, err)
			}
		}
	}

	// Gather GADGET_ITER_MEMBER programs: each iter program function carries an
	// ig:iter:<name> tag on its btf.Func (attached to the first instruction).
	for progName, p := range i.collectionSpec.Programs {
		if len(p.Instructions) == 0 {
			continue
		}
		fn := btf.FuncMetadata(&p.Instructions[0])
		if fn == nil {
			continue
		}
		for _, tag := range fn.Tags {
			kind, value, ok := parseIGTag(tag)
			if !ok || kind != igTagIter {
				continue
			}
			iterProgs[value] = append(iterProgs[value], progName)
		}
	}

	// Combine element type + program list into the legacy
	// "<name>___<struct>___<prog1>___..." encoding and reuse populateIterators.
	for name, structName := range iterTypes {
		if _, dup := i.iterators[name]; dup {
			continue
		}
		progs := iterProgs[name]
		if len(progs) == 0 {
			return fmt.Errorf("iterator %q (ig:iter_type) has no program tagged with GADGET_ITER_MEMBER(%s)", name, name)
		}
		// Sort for a deterministic program order (map iteration is random).
		sort.Strings(progs)
		parts := append([]string{name, structName}, progs...)
		if err := i.populateIterators(nil, strings.Join(parts, typeSplitter)); err != nil {
			return fmt.Errorf("handling ig:iter %q: %w", name, err)
		}
	}

	// Any ig:iter tags whose iterator has no ig:iter_type phantom are an error
	// (the element struct is required to resolve the event type).
	for name := range iterProgs {
		if _, ok := iterTypes[name]; !ok {
			if _, dup := i.iterators[name]; dup {
				continue
			}
			return fmt.Errorf("GADGET_ITER_MEMBER(%s) has no matching GADGET_ITER(%s, <type>)", name, name)
		}
	}

	return nil
}

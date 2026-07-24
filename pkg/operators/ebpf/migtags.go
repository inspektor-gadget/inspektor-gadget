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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// readMigratedDeclTags reads the ig: decl tags that are the new encoding of the
// legacy name-encoded magic globals (GADGET_PARAM -> ig:param, GADGET_MAPITER ->
// ig:mapiter, GADGET_ITER_TARGET_MAP -> ig:iter_target_map). It runs in
// analyze(), before fillParamDefaults(), alongside — not instead of — the legacy
// prefix walk (see pkg/operators/ebpf/types.go): a gadget built with the new
// macros carries ig: tags, while a pre-built old image carries only the
// gadget_*___* symbols. Both are supported permanently; the populate* helpers
// (and the guards here) are idempotent, so an object carrying both encodings is
// handled once.
func (i *ebpfInstance) readMigratedDeclTags(gadgetCtx operators.GadgetContext) error {
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
			}
		}
	}
	return nil
}

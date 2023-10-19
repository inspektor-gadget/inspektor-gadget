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

package tracer

import (
	"fmt"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
)

// getAnyMapElem returns any element of a map. If the map is empty, it returns nil, nil.
func getAnyMapElem[K comparable, V any](m map[K]V) (*K, *V) {
	for k, v := range m {
		return &k, &v
	}
	return nil, nil
}

func getEventTypeBTF(progContent []byte, metadata *types.GadgetMetadata) (*btf.Struct, error) {
	spec, err := loadSpec(progContent)
	if err != nil {
		return nil, err
	}

	switch {
	case len(metadata.Tracers) > 0:
		_, tracer := getAnyMapElem(metadata.Tracers)
		traceMap := spec.Maps[tracer.MapName]
		if traceMap == nil {
			return nil, fmt.Errorf("BPF map %q not found", tracer.MapName)
		}

		if traceMap.Value == nil {
			return nil, fmt.Errorf("BPF map %q does not have BTF information for its values", traceMap.Name)
		}

		valueStruct, ok := traceMap.Value.(*btf.Struct)
		if !ok {
			return nil, fmt.Errorf("value of BPF map %q is not a structure", traceMap.Name)
		}

		return valueStruct, nil
	default:
		return nil, fmt.Errorf("the gadget doesn't provide any compatible way to show information")
	}
}

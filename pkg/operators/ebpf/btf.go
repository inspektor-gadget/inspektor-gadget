// Copyright 2025 The Inspektor Gadget authors
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
	"slices"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	ebpfTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	seop "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
)

func (i *ebpfInstance) fixBTFStructs(typesCpy *btf.Spec) (*btf.Spec, error) {
	types := []btf.Type{}

	uint32T := &btf.Int{
		Size:     4,
		Encoding: btf.Unsigned,
	}
	charT := &btf.Int{
		Name:     "char",
		Size:     1,
		Encoding: btf.Signed, // TODO: Why ebpf operator requires signed for char?
	}

	types = append(types, uint32T, charT)

	for typ, err := range typesCpy.All() {
		if err != nil {
			return nil, fmt.Errorf("getting type: %w", err)
		}
		eventStructure, ok := typ.(*btf.Struct)
		if !ok {
			continue
		}

		found := false

		for _, member := range eventStructure.Members {
			_, typeNames := btfhelpers.GetType(member.Type)

			var seTypeName string

			if slices.Contains(typeNames, ebpfTypes.GadgetSeCwdName) {
				seTypeName = seop.CwdFieldName
			} else if slices.Contains(typeNames, ebpfTypes.GadgetSeExepathName) {
				seTypeName = seop.ExepathFieldName
			} else {
				continue
			}

			fieldSize := i.seFieldSizes[seTypeName]
			if fieldSize == 0 {
				// If the size is 0, we remove the member
				if err := removeBTFStructMember(eventStructure, member.Name); err != nil {
					return nil, fmt.Errorf("removing member %q from struct %q: %w", member.Name, eventStructure.Name, err)
				}
			} else {
				seType := &btf.Array{
					Index:  uint32T,
					Type:   charT,
					Nelems: uint32(fieldSize),
				}
				if err := replaceBTFStructMember(eventStructure, member.Name, seType); err != nil {
					return nil, fmt.Errorf("replacing member %q in struct %q with type %q: %w",
						member.Name, eventStructure.Name, seTypeName, err)
				}
			}

			found = true
		}

		if found {
			types = append(types, eventStructure)
		}
	}

	ret, err := btfhelpers.BuildSpec(types)
	if err != nil {
		return nil, fmt.Errorf("building BTF spec for event structure: %w", err)
	}

	return ret, nil
}

func findBTFStructMemberIndex(s *btf.Struct, memberName string) (int, error) {
	for i, m := range s.Members {
		if m.Name == memberName {
			return i, nil
		}
	}
	return -1, fmt.Errorf("member %q not found in struct %q", memberName, s.Name)
}

func removeBTFStructMember(s *btf.Struct, memberName string) error {
	return replaceBTFStructMember(s, memberName, nil)
}

// replaceBTFStructMember replaces memberName in struct s with typ. If typ is
// nil, the member is removed.
func replaceBTFStructMember(s *btf.Struct, memberName string, typ btf.Type) error {
	memberIdx, err := findBTFStructMemberIndex(s, memberName)
	if err != nil {
		return err
	}

	member := &s.Members[memberIdx]

	memberSize, err := btf.Sizeof(member.Type)
	if err != nil {
		return fmt.Errorf("getting size of member %q in struct %q: %w",
			memberName, s.Name, err)
	}

	newSize := int(0)
	if typ != nil {
		var err error
		newSize, err = btf.Sizeof(typ)
		if err != nil {
			return fmt.Errorf("getting size of new type for member %q in struct %q: %w",
				memberName, s.Name, err)
		}

		if newSize > memberSize {
			return fmt.Errorf("new size %d is bigger than current size %d for member %q in struct %q",
				newSize, memberSize, memberName, s.Name)
		}

		member.Type = typ
	}

	sizeDiff := memberSize - newSize
	s.Size -= uint32(sizeDiff)

	// shift all members after the resized one
	for i := memberIdx + 1; i < len(s.Members); i++ {
		s.Members[i].Offset -= btf.Bits(sizeDiff * 8)
	}

	if typ == nil {
		// remove the member
		s.Members = append(s.Members[:memberIdx], s.Members[memberIdx+1:]...)
	}

	return nil
}

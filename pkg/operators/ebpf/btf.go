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
	"math"
	"strconv"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
)

func flexStringParamName(name string) string {
	return fmt.Sprintf("%s-size", name)
}

func typeIsFlexString(typ btf.Type) bool {
	_, typeNames := btfhelpers.GetType(typ)

	// only check the top type name to avoid issues if somebody does something like:
	// typedef char              gadget_se_exepath;
	// typedef gadget_se_exepath gadget_se_cwd;
	if len(typeNames) == 0 {
		return false
	}

	switch typeNames[0] {
	case types.FlexStringTypeName, types.FlexBytesTypeName:
		return true
	default:
		return false
	}
}

func (i *ebpfInstance) fixFlexStrings(typesCpy *btf.Spec) (*btf.Spec, error) {
	uint32T := &btf.Int{
		Size:     4,
		Encoding: btf.Unsigned,
	}
	charT := &btf.Int{
		Name:     "char",
		Size:     1,
		Encoding: btf.Signed, // TODO: Why ebpf operator requires signed for char?
	}

	types := []btf.Type{}

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
			if !typeIsFlexString(member.Type) {
				continue
			}

			arr, ok := member.Type.(*btf.Array)
			if !ok {
				return nil, fmt.Errorf("type is not an array: %s", member.Type.TypeName())
			}
			under := btfhelpers.ResolveType(arr.Type)

			intT, ok := under.(*btf.Int)
			if !ok || intT.Size != 1 {
				return nil, fmt.Errorf("array type is not 1-byte big: %s", member.Type.TypeName())
			}

			var fieldSize int

			fieldSizeStr, ok := i.paramValues[flexStringParamName(member.Name)]
			if !ok {
				fieldSize, err = btf.Sizeof(member.Type)
				if err != nil {
					return nil, fmt.Errorf("getting size of member %q in struct %q: %w",
						member.Name, eventStructure.Name, err)
				}
			} else {
				fieldSize, err = strconv.Atoi(fieldSizeStr)
				if err != nil {
					return nil, fmt.Errorf("parsing size for member %q in struct %q: %w", member.Name, eventStructure.Name, err)
				}
			}

			i.logger.Debugf("Fixing member %q in struct %q with size %d\n", member.Name, eventStructure.Name, fieldSize)

			if fieldSize == 0 {
				// If the size is 0, we remove the member
				if err := removeBTFStructMember(eventStructure, member.Name); err != nil {
					return nil, fmt.Errorf("removing member %q from struct %q: %w", member.Name, eventStructure.Name, err)
				}
			} else {

				// Do this here to keep CodeQL happy, otherwise it complains about
				// possible integer overflow in the uint32 conversion
				if fieldSize < 0 || fieldSize > int(math.MaxUint32) {
					return nil, fmt.Errorf("size for member %q in struct %q out of uint32 range: %d", member.Name, eventStructure.Name, fieldSize)
				}

				seType := &btf.Array{
					Index:  uint32T,
					Type:   charT,
					Nelems: uint32(fieldSize),
				}
				if err := replaceBTFStructMember(eventStructure, member.Name, seType); err != nil {
					return nil, fmt.Errorf("replacing member %q in struct %q: %w", member.Name, eventStructure.Name, err)
				}
			}

			found = true
		}

		if found {
			types = append(types, eventStructure)
		}
	}

	// Now we need to fix the size of the maps that are using these structures
	for _, m := range i.collectionSpec.Maps {
		if m.Value == nil || m.Key == nil {
			continue
		}

		for _, typ := range types {
			// we need to compare the IDs because we can't compare the types
			// directly as one is a copy of the other
			typeID, err := typesCpy.TypeID(typ)
			if err != nil {
				return nil, fmt.Errorf("getting type ID: %w", err)
			}

			valueTypeID, err := i.collectionSpec.Types.TypeID(m.Value)
			if err != nil {
				return nil, fmt.Errorf("getting map type ID: %w", err)
			}
			if typeID == valueTypeID {
				m.Value = typ
				s, err := btf.Sizeof(typ)
				if err != nil {
					return nil, fmt.Errorf("getting size of type %s: %w", typ.TypeName(), err)
				}
				m.ValueSize = uint32(s)
			}

			keyTypeID, err := i.collectionSpec.Types.TypeID(m.Key)
			if err != nil {
				return nil, fmt.Errorf("getting map type ID: %w", err)
			}
			if typeID == keyTypeID {
				m.Key = typ
				s, err := btf.Sizeof(typ)
				if err != nil {
					return nil, fmt.Errorf("getting size of type %s: %w", typ.TypeName(), err)
				}
				m.KeySize = uint32(s)
			}
		}
	}

	types = append(types, uint32T, charT)

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
			return fmt.Errorf("getting size of new type for member %q in struct %q: %w", memberName, s.Name, err)
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

func (i *ebpfInstance) populateVariableSizeParams() error {
	for typ, err := range i.btfTypes.All() {
		if err != nil {
			return fmt.Errorf("iterating over types: %w", err)
		}

		typStruct, ok := typ.(*btf.Struct)
		if !ok {
			continue
		}

		for _, member := range typStruct.Members {
			if !typeIsFlexString(member.Type) {
				continue
			}

			memberSize, err := btf.Sizeof(member.Type)
			if err != nil {
				return fmt.Errorf("getting size of member %q in struct %q: %w",
					member.Name, typStruct.Name, err)
			}

			paramName := flexStringParamName(member.Name)
			i.params[paramName] = &param{
				Param: &api.Param{
					Key:          paramName,
					Description:  fmt.Sprintf("Size of the %s field", member.Name),
					TypeHint:     api.TypeInt,
					DefaultValue: fmt.Sprintf("%d", memberSize),
				},
			}
		}
	}
	return nil
}

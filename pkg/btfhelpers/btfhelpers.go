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

// Package btfhelpers provides a couple of helper functions to bridge Go's reflection system with
// types from BTF
package btfhelpers

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf/btf"
)

// GetType returns the reflect.Type for a given BTF type and the list of type names found while
// resolving it.
func GetType(typ btf.Type) (reflect.Type, []string) {
	var refType reflect.Type
	typeNames := []string{}

	if typ.TypeName() != "" {
		typeNames = append(typeNames, typ.TypeName())
	}

	switch typed := typ.(type) {
	case *btf.Array:
		arrType, arrayTypeNames := GetType(typed.Type)
		if arrType == nil {
			return nil, nil
		}
		typeNames = append(typeNames, arrayTypeNames...)
		refType = reflect.ArrayOf(int(typed.Nelems), arrType)
	case *btf.Typedef:
		switch typed := typ.(type) {
		case *btf.Typedef:
			refType, typeNames2 := GetType(typed.Type)
			typeNames = append(typeNames, typeNames2...)
			return refType, typeNames
		default:
			return GetType(typed)
		}
	case *btf.Volatile:
		return GetType(typed.Type)
	case *btf.Const:
		return GetType(typed.Type)
	default:
		refType = getSimpleType(typ)
	}

	return refType, typeNames
}

// GetUnderlyingType returns the underlying type of a typedef
func GetUnderlyingType(tf *btf.Typedef) btf.Type {
	switch typed := tf.Type.(type) {
	case *btf.Typedef:
		return GetUnderlyingType(typed)
	default:
		return typed
	}
}

// ResolveType returns the underlying type removing qualifiers like typedef,
// const, volatile.
func ResolveType(tf btf.Type) btf.Type {
	switch typed := tf.(type) {
	case *btf.Typedef:
		return ResolveType(typed.Type)
	case *btf.Volatile:
		return ResolveType(typed.Type)
	case *btf.Const:
		return ResolveType(typed.Type)
	default:
		return typed
	}
}

func getSimpleType(typ btf.Type) reflect.Type {
	switch typed := typ.(type) {
	case *btf.Int:
		switch typed.Encoding {
		case btf.Signed:
			switch typed.Size {
			case 1:
				return reflect.TypeOf(int8(0))
			case 2:
				return reflect.TypeOf(int16(0))
			case 4:
				return reflect.TypeOf(int32(0))
			case 8:
				return reflect.TypeOf(int64(0))
			}
		case btf.Unsigned:
			switch typed.Size {
			case 1:
				return reflect.TypeOf(uint8(0))
			case 2:
				return reflect.TypeOf(uint16(0))
			case 4:
				return reflect.TypeOf(uint32(0))
			case 8:
				return reflect.TypeOf(uint64(0))
			}
		case btf.Bool:
			return reflect.TypeOf(false)
		case btf.Char:
			return reflect.TypeOf(uint8(0))
		}
	case *btf.Float:
		switch typed.Size {
		case 4:
			return reflect.TypeOf(float32(0))
		case 8:
			return reflect.TypeOf(float64(0))
		}
	case *btf.Enum:
		if typed.Signed {
			switch typed.Size {
			case 1:
				return reflect.TypeOf(int8(0))
			case 2:
				return reflect.TypeOf(int16(0))
			case 4:
				return reflect.TypeOf(int32(0))
			case 8:
				return reflect.TypeOf(int64(0))
			}
		}

		switch typed.Size {
		case 1:
			return reflect.TypeOf(uint8(0))
		case 2:
			return reflect.TypeOf(uint16(0))
		case 4:
			return reflect.TypeOf(uint32(0))
		case 8:
			return reflect.TypeOf(uint64(0))
		}
	}
	return nil
}

func AppendTypesToSpec(spec *btf.Spec, types []btf.Type) (*btf.Spec, error) {
	allTypes := []btf.Type{}
	iterator := spec.Iterate()
	for iterator.Next() {
		allTypes = append(allTypes, iterator.Type)
	}

	builder, err := btf.NewBuilder(allTypes)
	if err != nil {
		return nil, fmt.Errorf("creating BTF builder: %w", err)
	}

	for _, typ := range types {
		if _, err := builder.Add(typ); err != nil {
			return nil, fmt.Errorf("adding types: %w", err)
		}
	}

	buf := []byte{}
	mergedBtfRaw, err := builder.Marshal(buf, nil)
	if err != nil {
		return nil, fmt.Errorf("marshalling BTF: %w", err)
	}

	newSpec, err := btf.LoadSpecFromReader(bytes.NewReader(mergedBtfRaw))
	if err != nil {
		return nil, fmt.Errorf("loading BTF spec: %w", err)
	}

	return newSpec, nil
}

func BtfInt(size uint32, encoding btf.IntEncoding) *btf.Int {
	return &btf.Int{
		Size:     size,
		Encoding: encoding,
	}
}

func BtfArray(indexT, valueT btf.Type, nelems uint32) *btf.Array {
	return &btf.Array{
		Index:  indexT,
		Type:   valueT,
		Nelems: nelems,
	}
}

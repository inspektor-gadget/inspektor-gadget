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

package datasource

import (
	"fmt"

	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func AsInt64Func[T constraints.Integer](extract func(Data) (T, error)) func(Data) int64 {
	return func(data Data) int64 {
		v, err := extract(data)
		if err != nil {
			return 0
		}
		return int64(v)
	}
}

func AsInt64(f FieldAccessor) (func(Data) int64, error) {
	switch f.Type() {
	default:
		return nil, fmt.Errorf("invalid field type for AsInt64: %s", f.Type())
	case api.Kind_Int8:
		return AsInt64Func(f.Int8), nil
	case api.Kind_Int16:
		return AsInt64Func(f.Int16), nil
	case api.Kind_Int32:
		return AsInt64Func(f.Int32), nil
	case api.Kind_Int64:
		return AsInt64Func(f.Int64), nil
	case api.Kind_Uint8:
		return AsInt64Func(f.Uint8), nil
	case api.Kind_Uint16:
		return AsInt64Func(f.Uint16), nil
	case api.Kind_Uint32:
		return AsInt64Func(f.Uint32), nil
	case api.Kind_Uint64:
		return AsInt64Func(f.Uint64), nil
	}
}

func AsFloat64Func[T constraints.Float](extract func(Data) (T, error)) func(Data) float64 {
	return func(data Data) float64 {
		v, err := extract(data)
		if err != nil {
			return 0
		}
		return float64(v)
	}
}

func AsFloat64(f FieldAccessor) (func(Data) float64, error) {
	switch f.Type() {
	default:
		return nil, fmt.Errorf("invalid field type for AsFloat64: %s", f.Type())
	case api.Kind_Float32:
		return AsFloat64Func(f.Float32), nil
	case api.Kind_Float64:
		return AsFloat64Func(f.Float64), nil
	}
}

// GetKeyValueFunc takes a FieldAccessor and returns a function that can convert Data to a key/value pair of types S/T
// using the primitive converters given; this is especially useful for the otel libraries which deal with different
// types for key/value pairs. Error checking is omitted here as it should a) have been done by type checking beforehand,
// and b) it is too costly when done in here. Instead, on error, the default values will be returned.
func GetKeyValueFunc[S ~string, T any](
	f FieldAccessor,
	nameOverride string,
	int64Fn func(int64) T,
	float64Fn func(float64) T,
	stringFn func(string) T,
) (func(Data) (S, T), error) {
	emptyVal := *new(T)
	name := f.Name()
	if nameOverride != "" {
		name = nameOverride
	}
	switch f.Type() {
	default:
		return nil, fmt.Errorf("unsupported field type for key: %s", f.Type())
	case api.Kind_String, api.Kind_CString:
		return func(data Data) (S, T) {
			val, err := f.String(data)
			if err != nil {
				return "", emptyVal
			}
			return S(name), stringFn(val)
		}, nil
	case api.Kind_Uint8,
		api.Kind_Uint16,
		api.Kind_Uint32,
		api.Kind_Uint64,
		api.Kind_Int8,
		api.Kind_Int16,
		api.Kind_Int32,
		api.Kind_Int64:
		asIntFn, _ := AsInt64(f) // error can't happen
		return func(data Data) (S, T) {
			return S(name), int64Fn(asIntFn(data))
		}, nil
	case api.Kind_Float32, api.Kind_Float64:
		asFloatFn, _ := AsFloat64(f) // error can't happen
		return func(data Data) (S, T) {
			return S(name), float64Fn(asFloatFn(data))
		}, nil
	}
}

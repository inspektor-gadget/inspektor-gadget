// Copyright 2022-2024 The Inspektor Gadget authors
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

package columns

import (
	"reflect"
	"strings"
)

// ToLowerStrings transforms the elements of an array of strings into lowercase.
func ToLowerStrings(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(in[i])
	}
	return in
}

func GetWidthFromType(kind reflect.Kind) int {
	switch kind {
	default:
		return 0
	case reflect.Uint8:
		return MaxCharsUint8
	case reflect.Int8:
		return MaxCharsInt8
	case reflect.Uint16:
		return MaxCharsUint16
	case reflect.Int16:
		return MaxCharsInt16
	case reflect.Uint32:
		return MaxCharsUint32
	case reflect.Int32:
		return MaxCharsInt32
	case reflect.Uint64, reflect.Uint:
		return MaxCharsUint64
	case reflect.Int64, reflect.Int:
		return MaxCharsInt64
	case reflect.Bool:
		return MaxCharsBool
	}
}

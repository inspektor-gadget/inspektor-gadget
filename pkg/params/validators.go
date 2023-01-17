// Copyright 2022-2023 The Inspektor Gadget authors
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

package params

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

type TypeHint string

const (
	TypeString TypeHint = "string"
	TypeInt    TypeHint = "int"
	TypeUint   TypeHint = "uint"
	TypeBool   TypeHint = "bool"
)

var typeHintValidators = map[TypeHint]ParamValidator{
	TypeInt:  ValidateNumber, // TODO: more specific
	TypeUint: ValidateNumber, // TODO: more specific
	TypeBool: ValidateBool,
}

type ParamValidator func(value string) error

func ValidateBool(value string) error {
	value = strings.ToLower(value)
	if value != "true" && value != "false" {
		return fmt.Errorf("expected 'true' or 'false'")
	}
	return nil
}

func ValidateNumber(value string) error {
	_, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("expected numeric value")
	}
	return nil
}

func ValidateNumberRange(min, max int64) func(value string) error {
	return func(value string) error {
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("expected numeric value")
		}
		if number < min || number > max {
			return fmt.Errorf("number out of range: got %d, expected min %d, max %d", number, min, max)
		}
		return nil
	}
}

func ValidateSlice(validator ParamValidator) func(value string) error {
	return func(value string) error {
		for i, val := range strings.Split(value, ",") {
			if err := validator(val); err != nil {
				return fmt.Errorf("entry #%d (%q): %w", i+1, val, err)
			}
		}
		return nil
	}
}

func ParamAsIntSlice[T int | int8 | int16 | int32 | int64](p *Param, target *[]T) {
	StringAsIntSlice(p.value, target)
}

func StringAsIntSlice[T int | int8 | int16 | int32 | int64](s string, target *[]T) {
	if s == "" {
		*target = []T{}
		return
	}
	in := strings.Split(s, ",")
	out := make([]T, 0, len(in))
	for _, entry := range in {
		n, _ := strconv.ParseInt(entry, 10, int(unsafe.Sizeof(*new(T))*8))
		out = append(out, T(n))
	}
	*target = out
}

func ParamAsUintSlice[T uint | uint8 | uint16 | uint32 | uint64](p *Param, target *[]T) {
	StringAsUintSlice(p.value, target)
}

func StringAsUintSlice[T uint | uint8 | uint16 | uint32 | uint64](s string, target *[]T) {
	if s == "" {
		*target = []T{}
		return
	}
	in := strings.Split(s, ",")
	out := make([]T, 0, len(in))
	for _, entry := range in {
		n, _ := strconv.ParseUint(entry, 10, int(unsafe.Sizeof(*new(T))*8))
		out = append(out, T(n))
	}
	*target = out
}

func ParamAsFloat[T float32 | float64](p *Param, target *T) {
	StringAsFloat(p.value, target)
}

func StringAsFloat[T float32 | float64](s string, target *T) {
	n, _ := strconv.ParseFloat(s, int(unsafe.Sizeof(*target)*8))
	*target = T(n)
}

func ParamAsInt[T int | int8 | int16 | int32 | int64](p *Param, target *T) {
	StringAsInt(p.value, target)
}

func StringAsInt[T int | int8 | int16 | int32 | int64](s string, target *T) {
	n, _ := strconv.ParseInt(s, 10, int(unsafe.Sizeof(*target)*8))
	*target = T(n)
}

func ParamAsUint[T uint | uint8 | uint16 | uint32 | uint64](p *Param, target *T) {
	StringAsUint(p.value, target)
}

func StringAsUint[T uint | uint8 | uint16 | uint32 | uint64](s string, target *T) {
	n, _ := strconv.ParseUint(s, 10, int(unsafe.Sizeof(*target)*8))
	*target = T(n)
}

func ParamAsString[T string](p *Param, target *T) {
	StringAsString(p.value, target)
}

func StringAsString[T string](s string, target *T) {
	*target = T(s)
}

func ParamAsStringSlice[T string](p *Param, target *[]T) {
	StringAsStringSlice(p.value, target)
}

func StringAsStringSlice[T string](s string, target *[]T) {
	if s == "" {
		*target = []T{}
		return
	}
	in := strings.Split(s, ",")
	out := make([]T, 0, len(in))
	for _, entry := range in {
		out = append(out, T(entry))
	}
	*target = out
}

func ParamAsBool(p *Param, target *bool) {
	StringAsBool(p.value, target)
}

func StringAsBool(s string, target *bool) {
	if strings.ToLower(s) == "true" {
		*target = true
		return
	}
	*target = false
}

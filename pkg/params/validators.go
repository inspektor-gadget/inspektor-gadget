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

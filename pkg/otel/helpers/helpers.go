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

package helpers

import (
	"fmt"
	"strconv"
	"strings"
)

func GetKeyValueFuncsFromAnnotations[S ~string, T any](
	annotations map[string]string,
	AnnotationAttributesPrefix string,
	AnnotationAttributesValueSuffix string,
	AnnotationAttributesTypeSuffix string,
	int64Fn func(int64) T,
	float64Fn func(float64) T,
	stringFn func(string) T,
) ([]func() (S, T), error) {
	var prep []func() (S, T)
	for k, v := range annotations {
		if attributePrefixed, ok := strings.CutPrefix(k, AnnotationAttributesPrefix); ok {
			attributeName, ok := strings.CutSuffix(attributePrefixed, AnnotationAttributesValueSuffix)
			if !ok {
				continue
			}
			// check (optional) type
			attributeType, _ := annotations[fmt.Sprintf("%s%s%s", AnnotationAttributesPrefix, attributeName, AnnotationAttributesTypeSuffix)]
			name := S(attributeName)
			switch attributeType {
			default:
				return nil, fmt.Errorf("invalid attribute type for attribute %q: %s", attributeName, attributeType)
			case "", "string":
				sv := stringFn(v)
				prep = append(prep, func() (S, T) {
					return name, sv
				})
			case "int64":
				i64, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid value for attribute %q of type %s: %w", attributeName, attributeType, err)
				}
				iv := int64Fn(i64)
				prep = append(prep, func() (S, T) {
					return name, iv
				})
			case "float64":
				f64, err := strconv.ParseFloat(v, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid value for attribute %q of type %s: %w", attributeName, attributeType, err)
				}
				sv := float64Fn(f64)
				prep = append(prep, func() (S, T) {
					return name, sv
				})
			}
		}
	}
	return prep, nil
}

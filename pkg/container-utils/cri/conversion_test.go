/*
Copyright 2021 The Kubernetes Authors.
Copyright 2023 The Inspektor Gadget authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* See:
 * https://github.com/kubernetes/kubernetes/blob/v1.25.9/pkg/kubelet/cri/remote/conversion_test.go
 */

package cri

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/inspektor-gadget/inspektor-gadget/internal/thirdparty/k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func TestMemoryEqual(t *testing.T) {
	testcases := []struct {
		a interface{}
		b interface{}
	}{
		{runtimeapi.ContainerFilter{}, v1alpha2.ContainerFilter{}},
	}

	for _, tc := range testcases {
		aType := reflect.TypeOf(tc.a)
		bType := reflect.TypeOf(tc.b)
		t.Run(aType.String(), func(t *testing.T) {
			assertEqualTypes(t, nil, aType, bType)
		})
	}
}

func assertEqualTypes(t *testing.T, path []string, a, b reflect.Type) {
	if a == b {
		return
	}

	if a.Kind() != b.Kind() {
		fatalTypeError(t, path, a, b, "mismatched Kind")
	}

	switch a.Kind() {
	case reflect.Struct:
		aFields := a.NumField()
		bFields := b.NumField()
		if aFields != bFields {
			fatalTypeError(t, path, a, b, "mismatched field count")
		}
		for i := 0; i < aFields; i++ {
			aField := a.Field(i)
			bField := b.Field(i)
			if aField.Name != bField.Name {
				fatalTypeError(t, path, a, b, fmt.Sprintf("mismatched field name %d: %s %s", i, aField.Name, bField.Name))
			}
			if aTag, bTag := stripEnum(aField.Tag), stripEnum(bField.Tag); aTag != bTag {
				fatalTypeError(t, path, a, b, fmt.Sprintf("mismatched field tag %d:\n%s\n%s\n", i, aTag, bTag))
			}
			if aField.Offset != bField.Offset {
				fatalTypeError(t, path, a, b, fmt.Sprintf("mismatched field offset %d: %v %v", i, aField.Offset, bField.Offset))
			}
			if aField.Anonymous != bField.Anonymous {
				fatalTypeError(t, path, a, b, fmt.Sprintf("mismatched field anonymous %d: %v %v", i, aField.Anonymous, bField.Anonymous))
			}
			if !reflect.DeepEqual(aField.Index, bField.Index) {
				fatalTypeError(t, path, a, b, fmt.Sprintf("mismatched field index %d: %v %v", i, aField.Index, bField.Index))
			}
			path = append(path, aField.Name)
			assertEqualTypes(t, path, aField.Type, bField.Type)
			path = path[:len(path)-1]
		}

	case reflect.Pointer, reflect.Slice:
		aElemType := a.Elem()
		bElemType := b.Elem()
		assertEqualTypes(t, path, aElemType, bElemType)

	case reflect.Int32:
		if a.Kind() != b.Kind() {
			fatalTypeError(t, path, a, b, "incompatible types")
		}

	default:
		fatalTypeError(t, path, a, b, "unhandled kind")
	}
}

// strip the enum value from the protobuf tag, since that doesn't impact the wire serialization and differs by package
func stripEnum(tagValue reflect.StructTag) reflect.StructTag {
	return reflect.StructTag(regexp.MustCompile(",enum=[^,]+").ReplaceAllString(string(tagValue), ""))
}

func fatalTypeError(t *testing.T, path []string, a, b reflect.Type, message string) {
	t.Helper()
	t.Fatalf("%s: %s: %s %s", strings.Join(path, ""), message, a, b)
}

func fillFields(s interface{}) {
	fillFieldsOffset(s, 0)
}

func fillFieldsOffset(s interface{}, offset int) {
	reflectType := reflect.TypeOf(s).Elem()
	reflectValue := reflect.ValueOf(s).Elem()

	for i := 0; i < reflectType.NumField(); i++ {
		field := reflectValue.Field(i)
		typeName := reflectType.Field(i).Name

		// Skipping protobuf internal values
		if strings.HasPrefix(typeName, "XXX_") {
			continue
		}

		fillField(field, i+offset)
	}
}

func fillField(field reflect.Value, v int) {
	switch field.Kind() {
	case reflect.Bool:
		field.SetBool(true)

	case reflect.Float32, reflect.Float64:
		field.SetFloat(float64(v))

	case reflect.String:
		field.SetString(fmt.Sprint(v))

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		field.SetInt(int64(v))

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		field.SetUint(uint64(v))

	case reflect.Map:
		field.Set(reflect.MakeMap(field.Type()))

	case reflect.Array, reflect.Slice:
		slice := reflect.MakeSlice(field.Type(), 1, 1)
		field.Set(slice)
		first := slice.Index(0)

		if first.Type().Kind() == reflect.Pointer {
			first.Set(reflect.New(first.Type().Elem()))
			fillFieldsOffset(first.Interface(), v)
		} else {
			fillField(first, v)
		}

	case reflect.Pointer:
		val := reflect.New(field.Type().Elem())
		field.Set(val)
		fillFieldsOffset(field.Interface(), v)

	case reflect.Struct:
		fillFieldsOffset(field.Addr().Interface(), v)
	}
}

func assertEqual(t *testing.T, a, b proto.Message) {
	aBytes, err := proto.Marshal(a)
	assert.Nil(t, err)

	bBytes, err := proto.Marshal(b)
	assert.Nil(t, err)

	assert.Equal(t, aBytes, bBytes)
}

func TestFromV1alpha2ListContainersResponse(t *testing.T) {
	from := &v1alpha2.ListContainersResponse{}
	fillFields(from)
	to := fromV1alpha2ListContainersResponse(from)
	assertEqual(t, from, to)
}

func TestFromV1alpha2ContainerStatusResponse(t *testing.T) {
	from := &v1alpha2.ContainerStatusResponse{}
	fillFields(from)
	to := fromV1alpha2ContainerStatusResponse(from)
	assertEqual(t, from, to)
}

func TestV1alpha2ContainerFilter(t *testing.T) {
	from := &runtimeapi.ContainerFilter{}
	fillFields(from)
	to := v1alpha2ContainerFilter(from)
	assertEqual(t, from, to)
}

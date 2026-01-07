/*
Copyright 2024 The Inspektor Gadget authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0
*/
package ebpfoperator

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestGetFieldKind_CharArrayDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		typ  reflect.Type
		tags []string
		want api.Kind
	}{
		{
			name: "char array -> CString",
			typ:  reflect.TypeOf([255]uint8{}),
			tags: []string{"type:char"},
			want: api.Kind_CString,
		},
		{
			name: "uint8 array -> ArrayOfUint8",
			typ:  reflect.TypeOf([10]uint8{}),
			tags: nil,
			want: api.ArrayOf(api.Kind_Uint8),
		},
		{
			name: "int8 array with type:char -> array of int8 (no cstring)",
			typ:  reflect.TypeOf([10]int8{}),
			tags: []string{"type:char"},
			want: api.ArrayOf(api.Kind_Int8),
		},
		{
			name: "array of arrays -> invalid",
			typ:  reflect.TypeOf([2][3]uint8{}),
			tags: nil,
			want: api.Kind_Invalid,
		},
		{
			name: "nil type -> invalid",
			typ:  nil,
			tags: nil,
			want: api.Kind_Invalid,
		},
		{
			name: "int32 array -> array of int32",
			typ:  reflect.TypeOf([3]int32{}),
			tags: nil,
			want: api.ArrayOf(api.Kind_Int32),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := getFieldKind(tt.typ, tt.tags)
			require.Equal(t, tt.want, got)
		})
	}
}

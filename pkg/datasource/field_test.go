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

package datasource

import (
	"maps"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestDataSourceFieldConfig(t *testing.T) {
	type testCase struct {
		name                string
		expectedAnnotations map[string]string
		expectedFlags       FieldFlag
		config              string
	}

	testCases := []testCase{
		{
			name:   "no-anotations",
			config: "",
		},
		{
			name: "columns.hidden",
			expectedAnnotations: map[string]string{
				"columns.hidden": "true",
			},
			expectedFlags: FieldFlagHidden,
			config: `
fields:
  foo:
    annotations:
      columns.hidden: true
`,
		},
		{
			name: "many-annotations",
			expectedAnnotations: map[string]string{
				"columns.width":    "40",
				"columns.maxwidth": "80",
				"foo-ann":          "yes",
			},
			expectedFlags: FieldFlagHidden,
			config: `
fields:
  foo:
    annotations:
      columns.width: 40
      columns.maxwidth: 80
      foo-ann: yes
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tc.config))
			require.NoError(t, err)

			ds, err := New(TypeArray, "myds", WithConfig(v))
			require.NoError(t, err)

			fooAcc, err := ds.AddField("foo", api.Kind_String)
			require.NoError(t, err)

			expectedAnnotations := maps.Clone(defaultFieldAnnotations)
			maps.Copy(expectedAnnotations, tc.expectedAnnotations)

			assert.Equal(t, fooAcc.Annotations(), expectedAnnotations)
		})
	}
}

func TestFieldFlag_Methods(t *testing.T) {
	t.Run("Uint32", func(t *testing.T) {
		flag := FieldFlagEmpty
		assert.Equal(t, uint32(1), flag.Uint32())

		flag = FieldFlagContainer
		assert.Equal(t, uint32(2), flag.Uint32())

		flag = FieldFlagHidden
		assert.Equal(t, uint32(4), flag.Uint32())

		flag = FieldFlagHasParent
		assert.Equal(t, uint32(8), flag.Uint32())

		flag = FieldFlagStaticMember
		assert.Equal(t, uint32(16), flag.Uint32())

		flag = FieldFlagUnreferenced
		assert.Equal(t, uint32(32), flag.Uint32())
	})

	t.Run("In", func(t *testing.T) {
		var flags uint32 = 0

		assert.False(t, FieldFlagEmpty.In(flags))
		assert.False(t, FieldFlagContainer.In(flags))

		flags |= FieldFlagEmpty.Uint32()
		assert.True(t, FieldFlagEmpty.In(flags))
		assert.False(t, FieldFlagContainer.In(flags))

		flags |= FieldFlagContainer.Uint32()
		assert.True(t, FieldFlagEmpty.In(flags))
		assert.True(t, FieldFlagContainer.In(flags))
		assert.False(t, FieldFlagHidden.In(flags))

		flags |= FieldFlagHasParent.Uint32()
		assert.True(t, FieldFlagEmpty.In(flags))
		assert.True(t, FieldFlagContainer.In(flags))
		assert.True(t, FieldFlagHasParent.In(flags))
		assert.False(t, FieldFlagHidden.In(flags))

		flags = FieldFlagEmpty.Uint32() | FieldFlagContainer.Uint32() | FieldFlagHidden.Uint32() |
			FieldFlagHasParent.Uint32() | FieldFlagStaticMember.Uint32() | FieldFlagUnreferenced.Uint32()

		assert.True(t, FieldFlagEmpty.In(flags))
		assert.True(t, FieldFlagContainer.In(flags))
		assert.True(t, FieldFlagHidden.In(flags))
		assert.True(t, FieldFlagHasParent.In(flags))
		assert.True(t, FieldFlagStaticMember.In(flags))
		assert.True(t, FieldFlagUnreferenced.In(flags))
	})

	t.Run("AddTo", func(t *testing.T) {
		var flags uint32 = 0

		FieldFlagEmpty.AddTo(&flags)
		assert.Equal(t, uint32(FieldFlagEmpty), flags)

		FieldFlagContainer.AddTo(&flags)
		assert.Equal(t, uint32(FieldFlagEmpty)|uint32(FieldFlagContainer), flags)

		FieldFlagEmpty.AddTo(&flags)
		assert.Equal(t, uint32(FieldFlagEmpty)|uint32(FieldFlagContainer), flags)

		FieldFlagHidden.AddTo(&flags)
		FieldFlagHasParent.AddTo(&flags)
		FieldFlagStaticMember.AddTo(&flags)
		FieldFlagUnreferenced.AddTo(&flags)

		expected := uint32(FieldFlagEmpty) | uint32(FieldFlagContainer) | uint32(FieldFlagHidden) |
			uint32(FieldFlagHasParent) | uint32(FieldFlagStaticMember) | uint32(FieldFlagUnreferenced)

		assert.Equal(t, expected, flags)
	})

	t.Run("RemoveFrom", func(t *testing.T) {
		expected := uint32(FieldFlagEmpty) | uint32(FieldFlagContainer) | uint32(FieldFlagHidden) |
			uint32(FieldFlagHasParent) | uint32(FieldFlagStaticMember) | uint32(FieldFlagUnreferenced)

		var flags uint32 = expected

		FieldFlagContainer.RemoveFrom(&flags)
		expected &^= uint32(FieldFlagContainer)
		assert.Equal(t, expected, flags)

		FieldFlagEmpty.RemoveFrom(&flags)
		expected &^= uint32(FieldFlagEmpty)
		assert.Equal(t, expected, flags)

		FieldFlagHidden.RemoveFrom(&flags)
		expected &^= uint32(FieldFlagHidden)
		assert.Equal(t, expected, flags)

		FieldFlagHasParent.RemoveFrom(&flags)
		FieldFlagStaticMember.RemoveFrom(&flags)
		FieldFlagUnreferenced.RemoveFrom(&flags)
		assert.Equal(t, uint32(0), flags)

		FieldFlagStaticMember.RemoveFrom(&flags)
		assert.Equal(t, uint32(0), flags)
	})
}

func TestFieldOptions(t *testing.T) {
	t.Run("WithFlags", func(t *testing.T) {
		ds, err := New(TypeArray, "testds")
		require.NoError(t, err)

		field1, err := ds.AddField("test1", api.Kind_String, WithFlags(FieldFlagHidden))
		require.NoError(t, err)
		assert.True(t, FieldFlagHidden.In(field1.Flags()))
		assert.False(t, FieldFlagEmpty.In(field1.Flags()))

		field2, err := ds.AddField("test2", api.Kind_String, WithFlags(FieldFlagHidden|FieldFlagEmpty))
		require.NoError(t, err)
		assert.True(t, FieldFlagHidden.In(field2.Flags()))
		assert.True(t, FieldFlagEmpty.In(field2.Flags()))
		assert.False(t, FieldFlagContainer.In(field2.Flags()))
	})

	t.Run("WithTags", func(t *testing.T) {
		ds, err := New(TypeArray, "testds")
		require.NoError(t, err)

		field1, err := ds.AddField("test1", api.Kind_String, WithTags("tag1"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"tag1"}, field1.Tags())

		field2, err := ds.AddField("test2", api.Kind_String, WithTags("tagA", "tagB"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"tagA", "tagB"}, field2.Tags())

		field3, err := ds.AddField("test3", api.Kind_String, WithTags("tag1"), WithTags("tag2"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"tag1", "tag2"}, field3.Tags())
	})

	t.Run("WithAnnotations", func(t *testing.T) {
		ds, err := New(TypeArray, "testds")
		require.NoError(t, err)

		field1, err := ds.AddField("test1", api.Kind_String, WithAnnotations(map[string]string{}))
		require.NoError(t, err)
		assert.NotNil(t, field1.Annotations())

		annotations := map[string]string{
			"key1": "value1",
			"key2": "value2",
		}

		field2, err := ds.AddField("test2", api.Kind_String, WithAnnotations(annotations))
		require.NoError(t, err)

		fieldAnnotations := field2.Annotations()
		assert.Equal(t, "value1", fieldAnnotations["key1"])
		assert.Equal(t, "value2", fieldAnnotations["key2"])

		annotations["key1"] = "modified"
		assert.Equal(t, "value1", field2.Annotations()["key1"])
	})

	t.Run("WithOrder", func(t *testing.T) {
		ds, err := New(TypeArray, "testds")
		require.NoError(t, err)

		field, err := ds.AddField("test", api.Kind_String, WithOrder(42))
		require.NoError(t, err)
		assert.NotNil(t, field)
	})

	t.Run("WithSameParentAs", func(t *testing.T) {
		ds, err := New(TypeArray, "testds")
		require.NoError(t, err)

		field1, err := ds.AddField("field1", api.Kind_String, WithSameParentAs(nil))
		require.NoError(t, err)
		assert.NotNil(t, field1)

		parent, err := ds.AddField("parent", api.Kind_String)
		require.NoError(t, err)

		field2, err := ds.AddField("field2", api.Kind_String, WithSameParentAs(parent))
		require.NoError(t, err)
		assert.False(t, FieldFlagHasParent.In(field2.Flags()))
	})
}

func TestCombinedFieldOptions(t *testing.T) {
	ds, err := New(TypeArray, "testds")
	require.NoError(t, err)

	field, err := ds.AddField("test", api.Kind_String,
		WithFlags(FieldFlagHidden),
		WithTags("tag1", "tag2"),
		WithAnnotations(map[string]string{"key": "value"}),
		WithOrder(42))
	require.NoError(t, err)

	assert.True(t, FieldFlagHidden.In(field.Flags()))
	assert.ElementsMatch(t, []string{"tag1", "tag2"}, field.Tags())
	assert.Equal(t, "value", field.Annotations()["key"])
}

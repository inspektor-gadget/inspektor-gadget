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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

// mockData implements the Data interface for testing
type mockData struct {
	data [][]byte
}

func (m *mockData) payload() [][]byte {
	return m.data
}

func (m *mockData) private() {}

func TestGetWidth(t *testing.T) {
	tests := []struct {
		name        string
		refType     reflect.Type
		value       string
		expectWidth int
		expectError bool
	}{
		{
			name:        "valid numeric width",
			value:       "10",
			expectWidth: 10,
			expectError: false,
		},
		{
			name:        "invalid width format",
			value:       "abc",
			expectWidth: 0,
			expectError: true,
		},
		{
			name:        "zero width",
			value:       "0",
			expectWidth: 0,
			expectError: false,
		},
		{
			name:        "negative width",
			value:       "-5",
			expectWidth: -5,
			expectError: false,
		},
		{
			name:        "type without reflect type",
			value:       "type",
			expectWidth: 0,
			expectError: true,
		},
		{
			name:        "type with integer reflect type",
			refType:     reflect.TypeOf(int(0)),
			value:       "type",
			expectWidth: columns.GetWidthFromType(reflect.Int),
			expectError: false,
		},
		{
			name:        "type with bool reflect type",
			refType:     reflect.TypeOf(bool(false)),
			value:       "type",
			expectWidth: columns.GetWidthFromType(reflect.Bool),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			width, err := getWidth(tt.refType, tt.value)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectWidth, width)
		})
	}
}

func TestDataTuple(t *testing.T) {
	mockDS := &dataSource{}
	mockD := &mockData{data: [][]byte{{1, 2, 3}}}

	dt := NewDataTuple(mockDS, mockD)
	assert.NotNil(t, dt)
	assert.Equal(t, mockDS, dt.ds)
	assert.Equal(t, mockD, dt.data)

	// Test with nil data
	dtNil := NewDataTuple(mockDS, nil)
	assert.NotNil(t, dtNil)
	assert.Equal(t, mockDS, dtNil.ds)
	assert.Nil(t, dtNil.data)
}

func createTestField(name string, annotations map[string]string) *field {
	f := &field{
		Name:        name,
		FullName:    name + "_field",
		Kind:        api.Kind_String,
		Tags:        []string{"tag1"},
		Annotations: annotations,
	}
	return f
}

func TestColumns(t *testing.T) {
	tests := []struct {
		name        string
		ds          *dataSource
		expectError bool
	}{
		{
			name: "basic string field",
			ds: &dataSource{
				fields: []*field{
					createTestField("test", map[string]string{
						metadatav1.ColumnsWidthAnnotation: "20",
					}),
				},
				fieldMap: map[string]*field{
					"test": createTestField("test", map[string]string{
						metadatav1.ColumnsWidthAnnotation: "20",
					}),
				},
			},
			expectError: false,
		},
		{
			name: "field with invalid alignment",
			ds: &dataSource{
				fields: []*field{
					createTestField("test", map[string]string{
						metadatav1.ColumnsAlignmentAnnotation: "invalid",
					}),
				},
				fieldMap: map[string]*field{
					"test": createTestField("test", map[string]string{
						metadatav1.ColumnsAlignmentAnnotation: "invalid",
					}),
				},
			},
			expectError: true,
		},
		{
			name: "field with alignment left",
			ds: &dataSource{
				fields: []*field{
					createTestField("test", map[string]string{
						metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentLeft),
					}),
				},
				fieldMap: map[string]*field{
					"test": createTestField("test", map[string]string{
						metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentLeft),
					}),
				},
			},
			expectError: false,
		},
		{
			name: "field with replacement",
			ds: &dataSource{
				fields: []*field{
					{
						Name:     "original",
						FullName: "original_field",
						Kind:     api.Kind_String,
						Annotations: map[string]string{
							ColumnsReplaceAnnotation: "replacement",
						},
					},
					{
						Name:     "replacement",
						FullName: "replacement_field",
						Kind:     api.Kind_String,
					},
				},
				fieldMap: map[string]*field{
					"original": {
						Name:     "original",
						FullName: "original_field",
						Kind:     api.Kind_String,
						Annotations: map[string]string{
							ColumnsReplaceAnnotation: "replacement",
						},
					},
					"replacement": {
						Name:     "replacement",
						FullName: "replacement_field",
						Kind:     api.Kind_String,
					},
				},
			},
			expectError: false,
		},
		{
			name: "field with non-existent replacement",
			ds: &dataSource{
				fields: []*field{
					{
						Name:     "original",
						FullName: "original_field",
						Annotations: map[string]string{
							ColumnsReplaceAnnotation: "non_existent",
						},
					},
				},
				fieldMap: map[string]*field{
					"original": {
						Name:     "original",
						FullName: "original_field",
						Annotations: map[string]string{
							ColumnsReplaceAnnotation: "non_existent",
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "field with ellipsis configuration",
			ds: &dataSource{
				fields: []*field{
					createTestField("test", map[string]string{
						metadatav1.ColumnsEllipsisAnnotation: string(metadatav1.EllipsisEnd),
					}),
				},
				fieldMap: map[string]*field{
					"test": createTestField("test", map[string]string{
						metadatav1.ColumnsEllipsisAnnotation: string(metadatav1.EllipsisEnd),
					}),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cols, err := tt.ds.Columns()

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, cols)
		})
	}
}

func TestParser(t *testing.T) {
	tests := []struct {
		name        string
		ds          *dataSource
		expectError bool
	}{
		{
			name: "valid parser creation",
			ds: &dataSource{
				fields: []*field{
					createTestField("test", nil),
				},
			},
			expectError: false,
		},
		{
			name: "parser with invalid field",
			ds: &dataSource{
				fields: []*field{
					{
						Name: "test",
						Annotations: map[string]string{
							metadatav1.ColumnsAlignmentAnnotation: "invalid",
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := tt.ds.Parser()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, parser)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, parser)
		})
	}
}

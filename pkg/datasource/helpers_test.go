package datasource

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockData struct {
	intVal    int64
	uintVal   uint64
	floatVal  float64
	stringVal string
	payloads  [][]byte
}

func (m mockData) private()          {}
func (m mockData) payload() [][]byte { return m.payloads }

type mockFieldAccessor struct {
	name        string
	kindType    api.Kind
	annotations map[string]string
	tags        []string
	flags       uint32
	failExtract bool
}

func (m mockFieldAccessor) Name() string                                  { return m.name }
func (m mockFieldAccessor) FullName() string                              { return m.name }
func (m mockFieldAccessor) Type() api.Kind                                { return m.kindType }
func (m mockFieldAccessor) Size() uint32                                  { return 0 }
func (m mockFieldAccessor) IsRequested() bool                             { return true }
func (m mockFieldAccessor) Parent() FieldAccessor                         { return nil }
func (m mockFieldAccessor) SubFields() []FieldAccessor                    { return nil }
func (m mockFieldAccessor) Flags() uint32                                 { return m.flags }
func (m mockFieldAccessor) Get(d Data) []byte                             { return nil }
func (m mockFieldAccessor) Set(d Data, value []byte) error                { return nil }
func (m mockFieldAccessor) Rename(string) error                           { return nil }
func (m mockFieldAccessor) RemoveReference(bool)                          {}
func (m mockFieldAccessor) SetHidden(bool, bool)                          {}
func (m mockFieldAccessor) GetSubFieldsWithTag(...string) []FieldAccessor { return nil }
func (m mockFieldAccessor) AddSubField(string, api.Kind, ...FieldOption) (FieldAccessor, error) {
	return nil, nil
}

func (m mockFieldAccessor) Tags() []string {
	if m.tags == nil {
		return []string{}
	}
	return m.tags
}

func (m mockFieldAccessor) AddTags(tags ...string) {
	m.tags = append(m.tags, tags...)
}

func (m mockFieldAccessor) HasAllTagsOf(tags ...string) bool { return false }
func (m mockFieldAccessor) HasAnyTagsOf(tags ...string) bool { return false }

func (m mockFieldAccessor) Annotations() map[string]string {
	if m.annotations == nil {
		return map[string]string{}
	}
	return m.annotations
}

func (m mockFieldAccessor) AddAnnotation(key, value string) {
	if m.annotations == nil {
		m.annotations = make(map[string]string)
	}
	m.annotations[key] = value
}

func (m mockFieldAccessor) Int8(data Data) (int8, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return int8(d.intVal), nil
}

func (m mockFieldAccessor) Int16(data Data) (int16, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return int16(d.intVal), nil
}

func (m mockFieldAccessor) Int32(data Data) (int32, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return int32(d.intVal), nil
}

func (m mockFieldAccessor) Int64(data Data) (int64, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return d.intVal, nil
}

func (m mockFieldAccessor) Uint8(data Data) (uint8, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return uint8(d.uintVal), nil
}

func (m mockFieldAccessor) Uint16(data Data) (uint16, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return uint16(d.uintVal), nil
}

func (m mockFieldAccessor) Uint32(data Data) (uint32, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return uint32(d.uintVal), nil
}

func (m mockFieldAccessor) Uint64(data Data) (uint64, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return d.uintVal, nil
}

func (m mockFieldAccessor) Float32(data Data) (float32, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return float32(d.floatVal), nil
}

func (m mockFieldAccessor) Float64(data Data) (float64, error) {
	if m.failExtract {
		return 0, assert.AnError
	}
	d := data.(mockData)
	return d.floatVal, nil
}
func (m mockFieldAccessor) String(data Data) (string, error) {
	if m.failExtract {
		return "", assert.AnError
	}
	d := data.(mockData)
	return d.stringVal, nil
}

func (m mockFieldAccessor) Bytes(Data) ([]byte, error) { return nil, nil }
func (m mockFieldAccessor) Bool(Data) (bool, error)    { return false, nil }

func (m mockFieldAccessor) Uint8Array(Data) ([]uint8, error)     { return nil, nil }
func (m mockFieldAccessor) Uint16Array(Data) ([]uint16, error)   { return nil, nil }
func (m mockFieldAccessor) Uint32Array(Data) ([]uint32, error)   { return nil, nil }
func (m mockFieldAccessor) Uint64Array(Data) ([]uint64, error)   { return nil, nil }
func (m mockFieldAccessor) Int8Array(Data) ([]int8, error)       { return nil, nil }
func (m mockFieldAccessor) Int16Array(Data) ([]int16, error)     { return nil, nil }
func (m mockFieldAccessor) Int32Array(Data) ([]int32, error)     { return nil, nil }
func (m mockFieldAccessor) Int64Array(Data) ([]int64, error)     { return nil, nil }
func (m mockFieldAccessor) Float32Array(Data) ([]float32, error) { return nil, nil }
func (m mockFieldAccessor) Float64Array(Data) ([]float64, error) { return nil, nil }

func (m mockFieldAccessor) PutUint8(Data, uint8) error     { return nil }
func (m mockFieldAccessor) PutUint16(Data, uint16) error   { return nil }
func (m mockFieldAccessor) PutUint32(Data, uint32) error   { return nil }
func (m mockFieldAccessor) PutUint64(Data, uint64) error   { return nil }
func (m mockFieldAccessor) PutInt8(Data, int8) error       { return nil }
func (m mockFieldAccessor) PutInt16(Data, int16) error     { return nil }
func (m mockFieldAccessor) PutInt32(Data, int32) error     { return nil }
func (m mockFieldAccessor) PutInt64(Data, int64) error     { return nil }
func (m mockFieldAccessor) PutFloat32(Data, float32) error { return nil }
func (m mockFieldAccessor) PutFloat64(Data, float64) error { return nil }
func (m mockFieldAccessor) PutString(Data, string) error   { return nil }
func (m mockFieldAccessor) PutBytes(Data, []byte) error    { return nil }
func (m mockFieldAccessor) PutBool(Data, bool) error       { return nil }

func TestAsInt64(t *testing.T) {
	tests := []struct {
		name        string
		kind        api.Kind
		input       mockData
		expected    int64
		failExtract bool
		wantErr     bool
	}{
		{
			name:     "Int8 conversion",
			kind:     api.Kind_Int8,
			input:    mockData{intVal: 42},
			expected: 42,
		},
		{
			name:     "Int16 conversion",
			kind:     api.Kind_Int16,
			input:    mockData{intVal: 1000},
			expected: 1000,
		},
		{
			name:     "Int32 conversion",
			kind:     api.Kind_Int32,
			input:    mockData{intVal: 100000},
			expected: 100000,
		},
		{
			name:     "Int64 conversion",
			kind:     api.Kind_Int64,
			input:    mockData{intVal: 9223372036854775807},
			expected: 9223372036854775807,
		},
		{
			name:     "Uint8 conversion",
			kind:     api.Kind_Uint8,
			input:    mockData{uintVal: 255},
			expected: 255,
		},
		{
			name:     "Uint16 conversion",
			kind:     api.Kind_Uint16,
			input:    mockData{uintVal: 65535},
			expected: 65535,
		},
		{
			name:     "Uint32 conversion",
			kind:     api.Kind_Uint32,
			input:    mockData{uintVal: 4294967295},
			expected: 4294967295,
		},
		{
			name:     "Uint64 conversion",
			kind:     api.Kind_Uint64,
			input:    mockData{uintVal: 18446744073709551615},
			expected: -1,
		},
		{
			name:        "Error in extraction",
			kind:        api.Kind_Int64,
			failExtract: true,
			expected:    0,
		},
		{
			name:    "Invalid type",
			kind:    api.Kind_Float32,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := mockFieldAccessor{
				name:        "test",
				kindType:    tt.kind,
				failExtract: tt.failExtract,
			}

			converter, err := AsInt64(accessor)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			result := converter(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAsFloat64(t *testing.T) {
	tests := []struct {
		name        string
		kind        api.Kind
		input       mockData
		expected    float64
		failExtract bool
		wantErr     bool
	}{
		{
			name:     "Float32 conversion",
			kind:     api.Kind_Float32,
			input:    mockData{floatVal: 42.5},
			expected: 42.5,
		},
		{
			name:     "Float64 conversion",
			kind:     api.Kind_Float64,
			input:    mockData{floatVal: 3.14159},
			expected: 3.14159,
		},
		{
			name:        "Error in extraction",
			kind:        api.Kind_Float64,
			failExtract: true,
			expected:    0,
		},
		{
			name:    "Invalid type",
			kind:    api.Kind_Int32,
			wantErr: true,
		},
		{
			name:     "Zero value",
			kind:     api.Kind_Float64,
			input:    mockData{floatVal: 0.0},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := mockFieldAccessor{
				name:        "test",
				kindType:    tt.kind,
				failExtract: tt.failExtract,
			}

			converter, err := AsFloat64(accessor)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			result := converter(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
func TestGetKeyValueFunc(t *testing.T) {
	tests := []struct {
		name          string
		kind          api.Kind
		input         mockData
		expectedKey   string
		expectedValue interface{}
		failExtract   bool
		wantErr       bool
	}{
		{
			name:          "String conversion",
			kind:          api.Kind_String,
			input:         mockData{stringVal: "test"},
			expectedKey:   "testField",
			expectedValue: "test",
		},
		{
			name:          "CString conversion",
			kind:          api.Kind_CString,
			input:         mockData{stringVal: "test"},
			expectedKey:   "testField",
			expectedValue: "test",
		},
		{
			name:          "Int64 conversion",
			kind:          api.Kind_Int64,
			input:         mockData{intVal: 42},
			expectedKey:   "testField",
			expectedValue: int64(42),
		},
		{
			name:          "Float64 conversion",
			kind:          api.Kind_Float64,
			input:         mockData{floatVal: 3.14},
			expectedKey:   "testField",
			expectedValue: 3.14,
		},
		{
			name:          "Int64 extraction error",
			kind:          api.Kind_Int64,
			failExtract:   true,
			expectedKey:   "testField",
			expectedValue: int64(0),
		},
		{
			name:          "Float64 extraction error",
			kind:          api.Kind_Float64,
			failExtract:   true,
			expectedKey:   "testField",
			expectedValue: float64(0),
		},
		{
			name:    "Unsupported type",
			kind:    api.Kind_Bool,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := mockFieldAccessor{
				name:        "testField",
				kindType:    tt.kind,
				failExtract: tt.failExtract,
			}

			kvFunc, err := GetKeyValueFunc[string, interface{}](
				accessor,
				func(i int64) interface{} { return i },
				func(f float64) interface{} { return f },
				func(s string) interface{} { return s },
			)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			key, value := kvFunc(tt.input)
			assert.Equal(t, tt.expectedKey, key)
			assert.Equal(t, tt.expectedValue, value, "Test case: %s", tt.name)
		})
	}
}

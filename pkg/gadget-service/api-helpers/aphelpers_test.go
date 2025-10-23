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

// Package apihelpers provides some helper functions for the API package; these were extracted into this package
// to avoid having additional dependencies on the API package itself
package apihelpers

import (
	"errors"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/stretchr/testify/require"
)

func TestParamDescsToParams(t *testing.T) {
	tests := []struct {
		name     string
		input    params.ParamDescs
		expected api.Params
	}{
		{
			name:     "empty",
			input:    nil,
			expected: nil,
		},
		{
			name: "single param",
			input: params.ParamDescs{
				{
					Key:            "param1",
					Description:    "A sample parameter",
					DefaultValue:   "default",
					TypeHint:       "string",
					Title:          "Parameter 1",
					Alias:          "p1",
					Tags:           []string{"tag1", "tag2"},
					ValueHint:      "hint",
					PossibleValues: []string{"val1", "val2"},
					IsMandatory:    true,
				},
			},
			expected: api.Params{
				{
					Key:            "param1",
					Description:    "A sample parameter",
					DefaultValue:   "default",
					TypeHint:       "string",
					Title:          "Parameter 1",
					Alias:          "p1",
					Tags:           []string{"tag1", "tag2"},
					ValueHint:      "hint",
					PossibleValues: []string{"val1", "val2"},
					IsMandatory:    true,
				},
			},
		},

		{
			name: "multiple params",
			input: params.ParamDescs{
				{
					Key:            "param2",
					Description:    "multiple params",
					DefaultValue:   "default",
					TypeHint:       "string",
					Title:          "Parameter 1",
					Alias:          "p1",
					Tags:           []string{"tag1", "tag2"},
					ValueHint:      "hint1",
					PossibleValues: []string{"val1", "val2"},
					IsMandatory:    true,
				},
				{
					Key:            "param2",
					Description:    "mutliple params",
					DefaultValue:   "default",
					TypeHint:       "string",
					Title:          "Parameter 2",
					Alias:          "p2",
					Tags:           []string{"tag1", "tag2"},
					ValueHint:      "hint",
					PossibleValues: []string{"val4", "val2"},
					IsMandatory:    false,
				},
			},
			expected: api.Params{
				{
					Key:            "param2",
					Description:    "multiple params",
					DefaultValue:   "default",
					TypeHint:       "string",
					Title:          "Parameter 1",
					Alias:          "p1",
					Tags:           []string{"tag1", "tag2"},
					ValueHint:      "hint1",
					PossibleValues: []string{"val1", "val2"},
					IsMandatory:    true,
				},
				{
					Key:            "param2",
					Description:    "mutliple params",
					DefaultValue:   "default",
					TypeHint:       "string",
					Title:          "Parameter 2",
					Alias:          "p2",
					Tags:           []string{"tag1", "tag2"},
					ValueHint:      "hint",
					PossibleValues: []string{"val4", "val2"},
					IsMandatory:    false,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ParamDescsToParams(test.input)
			require.Equal(t, test.expected, got)
		})
	}
}

func TestParamToParamDesc(t *testing.T) {
	tests := []struct {
		name     string
		input    *api.Param
		expected *params.ParamDesc
	}{
		{
			name: "single param",
			input: &api.Param{
				Key:            "param1",
				Description:    "A sample parameter",
				DefaultValue:   "default",
				TypeHint:       "string",
				Title:          "Parameter 1",
				Alias:          "p1",
				Tags:           []string{"tag1", "tag2"},
				ValueHint:      "hint",
				PossibleValues: []string{"val1", "val2"},
				IsMandatory:    true,
			},
			expected: &params.ParamDesc{
				Key:            "param1",
				Description:    "A sample parameter",
				DefaultValue:   "default",
				TypeHint:       params.TypeHint("string"),
				Title:          "Parameter 1",
				Alias:          "p1",
				Tags:           []string{"tag1", "tag2"},
				ValueHint:      params.ValueHint("hint"),
				PossibleValues: []string{"val1", "val2"},
				IsMandatory:    true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ParamToParamDesc(test.input)
			require.Equal(t, test.expected, got)
		})
	}
}

func TestToParamDescs(t *testing.T) {
	tests := []struct {
		name       string
		p          api.Params
		paramDescs *params.ParamDesc
	}{
		{
			name: "appending to paramDescs",
			p: api.Params{
				{
					Key:         "Key",
					Description: "Description",
				},
			},
			paramDescs: &params.ParamDesc{
				Key:         "Key",
				Description: "Description",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ans := ToParamDescs(test.p)
			for _, desc := range ans {
				require.Equal(t, test.paramDescs, desc)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		p    api.Params
		v    api.ParamValues
		err  error
	}{
		{
			name: "when value is nil",
			p: api.Params{
				{
					Key:         "test",
					Description: "Description",
				},
			},
			v:   api.ParamValues{},
			err: nil,
		},

		{
			name: "when value is not nil but got error",
			p: api.Params{
				{
					Key:            "color",
					PossibleValues: []string{"yellow", "black", "green"},
				},
			},
			v: api.ParamValues{
				"color": "white",
			},
			err: errors.New("invalid value \"white\" as \"color\": valid values are: yellow, black, green"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(test.p, test.v)
			require.Equal(t, test.err, err)
		})
	}
}

func TestGetStringValuesPerDataSource(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    map[string]string
		expectedErr bool
	}{
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:     "valid without datasource",
			input:    "50",
			expected: map[string]string{"": "50"},
		},
		{
			name:     "valid with datasource",
			input:    "datasource1:10",
			expected: map[string]string{"datasource1": "10"},
		},
		{
			name:     "valid with multiple datasources",
			input:    "datasource1:10,datasource2:20",
			expected: map[string]string{"datasource1": "10", "datasource2": "20"},
		},
		{
			name:     "valid with empty element",
			input:    "datasource1:10,",
			expected: map[string]string{"datasource1": "10"},
		},
		{
			name:     "valid with empty string value",
			input:    "datasource1:10,datasource2:",
			expected: map[string]string{"datasource1": "10", "datasource2": ""},
		},
		{
			name:     "valid with non-number value",
			input:    "datasource1:foo",
			expected: map[string]string{"datasource1": "foo"},
		},
		{
			name:        "invalid mixing datasource and no datasource",
			input:       "10,datasource1:20",
			expectedErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := GetStringValuesPerDataSource(test.input)
			if test.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.expected, got)
		})
	}
}

func TestGetIntValuesPerDataSource(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    map[string]int
		expectedErr bool
	}{
		{
			name:     "empty input",
			input:    "",
			expected: map[string]int{},
		},
		{
			name:     "valid without datasource",
			input:    "50",
			expected: map[string]int{"": 50},
		},
		{
			name:     "valid with datasource",
			input:    "datasource1:10",
			expected: map[string]int{"datasource1": 10},
		},
		{
			name:     "valid with multiple datasources",
			input:    "datasource1:10,datasource2:20",
			expected: map[string]int{"datasource1": 10, "datasource2": 20},
		},
		{
			name:     "valid with empty element",
			input:    "datasource1:10,",
			expected: map[string]int{"datasource1": 10},
		},
		{
			name:        "invalid with empty string value",
			input:       "datasource1:10,datasource2:",
			expectedErr: true,
		},
		{
			name:        "invalid with invalid number",
			input:       "datasource1:foo",
			expectedErr: true,
		},
		{
			name:        "invalid mixing datasource and no datasource",
			input:       "10,datasource1:20",
			expectedErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := GetIntValuesPerDataSource(test.input)
			if test.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.expected, got)
		})
	}
}

func TestGetDurationValuesPerDataSource(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    map[string]time.Duration
		expectedErr bool
	}{
		{
			name:     "empty input",
			input:    "",
			expected: map[string]time.Duration{},
		},
		{
			name:     "valid without datasource",
			input:    "50s",
			expected: map[string]time.Duration{"": 50 * time.Second},
		},
		{
			name:     "valid with datasource",
			input:    "datasource1:10h",
			expected: map[string]time.Duration{"datasource1": 10 * time.Hour},
		},
		{
			name:     "valid with multiple datasources",
			input:    "datasource1:10s,datasource2:20s",
			expected: map[string]time.Duration{"datasource1": 10 * time.Second, "datasource2": 20 * time.Second},
		},
		{
			name:     "valid with empty element",
			input:    "datasource1:10h,",
			expected: map[string]time.Duration{"datasource1": 10 * time.Hour},
		},
		{
			name:        "invalid with empty string value",
			input:       "datasource1:10,datasource2:",
			expectedErr: true,
		},
		{
			name:        "invalid with invalid time duration (string)",
			input:       "datasource1:foo",
			expectedErr: true,
		},
		{
			name:        "invalid mixing datasource and no datasource",
			input:       "10,datasource1:20",
			expectedErr: true,
		},
		{
			name:        "invalid with invalid time duration (no unit)",
			input:       "datasource1:10",
			expectedErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := GetDurationValuesPerDataSource(test.input)
			if test.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.expected, got)
		})
	}
}

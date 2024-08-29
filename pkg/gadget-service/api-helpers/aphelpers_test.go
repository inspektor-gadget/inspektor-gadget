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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

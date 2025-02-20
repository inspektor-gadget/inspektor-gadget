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

// Package apihelpers provides some helper functions for the API package; these were extracted into this package
// to avoid having additional dependencies on the API package itself

package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidInstanceID(t *testing.T) {
	tests := []struct {
		name     string
		instance string
		expected bool
	}{
		{
			name:     "valid instance",
			instance: "1234",
			expected: false,
		},
		{
			name:     "invalid instance",
			instance: "abcd",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := IsValidInstanceID(test.instance)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestIsValidInstanceName(t *testing.T) {
	tests := []struct {
		name     string
		instance string
		expected bool
	}{
		{
			name:     "valid instance when instance is number",
			instance: "1234",
			expected: true,
		},
		{
			name:     "invalid instance when instance is string",
			instance: "abcd",
			expected: true,
		},
		{
			name:     "invalid instance when instance is empty",
			instance: "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := IsValidInstanceName(test.instance)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestAddPrefix(t *testing.T) {
	pv := Params{
		{
			Key: "key1",
		},
		{
			Key: "key2",
		},
		{
			Key: "key3",
		},
	}

	expected := Params{
		{
			Key:    "key1",
			Prefix: "prefix.",
		},
		{
			Key:    "key2",
			Prefix: "prefix.",
		},
		{
			Key:    "key3",
			Prefix: "prefix.",
		},
	}
	res := pv.AddPrefix("prefix")
	assert.Equal(t, expected, res)
}

func TestParseSocketAddress(t *testing.T) {
	tests := []struct {
		name          string
		addr          string
		socketType    string
		socketPath    string
		expectedError error
	}{
		{
			name:          "empty address",
			addr:          "",
			socketType:    "",
			socketPath:    "",
			expectedError: errors.New("invalid type \"\" for socket; please use 'unix' or 'tcp'"),
		},
		{
			name:       "unix address",
			addr:       "unix:/var/run/docker.sock",
			socketType: "unix",
			socketPath: "/var/run/docker.sock",
		},
		{
			name:          "invalid address",
			addr:          "tcp://",
			socketType:    "",
			socketPath:    "",
			expectedError: errors.New("invalid tcp socket address 'tcp://'. Use something like 'tcp://127.0.0.1:1234'"),
		},
		{
			name:          "invalid address",
			addr:          "tcp://127.0.0.1:1234",
			socketType:    "tcp",
			socketPath:    "127.0.0.1:1234",
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, path, err := ParseSocketAddress(test.addr)
			fmt.Println(res, err, path)
			assert.Equal(t, test.expectedError, err)
			assert.Equal(t, test.socketType, res)
			assert.Equal(t, test.socketPath, path)
		})
	}
}

func TestSplitStringWithEscape(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		sep    rune
		output []string
	}{
		{
			name:   "non-empty string",
			s:      "a,b,c",
			sep:    ',',
			output: []string{"a", "b", "c"},
		},
		{
			name:   "something",
			s:      "a\\,b,c",
			sep:    ',',
			output: []string{"a,b", "c"},
		},
		{
			name:   "new",
			s:      "ad",
			sep:    ',',
			output: []string{"ad"},
		},
		{
			name:   "",
			s:      "",
			sep:    ',',
			output: []string{},
		},
		{
			name:   "empty string",
			s:      "",
			sep:    '\\',
			output: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := SplitStringWithEscape(test.s, test.sep)
			if test.s == "" {
				test.output = nil
			}
			assert.Equal(t, test.output, res)
		})
	}
}

func TestExtractPrefixedValues(t *testing.T) {
	tests := []struct {
		name     string
		pv       ParamValues
		prefix   string
		expected ParamValues
	}{
		{
			name: "empty prefix",
			pv: ParamValues{
				"prgsgs.key1": "value1",
			},
			prefix:   "",
			expected: ParamValues{},
		},
		{
			name: "non-empty prefix",
			pv: ParamValues{
				"prgsgs.key1": "value1",
				"prgsgs.key2": "value2",
				"prgsgs.key3": "value3",
			},
			prefix: "prgsgs",
			expected: ParamValues{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
		},
		{
			name:     "non-empty prefix",
			pv:       ParamValues{},
			prefix:   "prgsgs",
			expected: ParamValues{},
		},
		{
			name: "non-empty prefix",
			pv: ParamValues{
				"prgsgs.key1": "value1",
				"prgsgs.key2": "value2",
				"prg.key3":    "value3",
			},
			prefix: "prgsgs",
			expected: ParamValues{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := test.pv.ExtractPrefixedValues(test.prefix)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestNewInstanceID(t *testing.T) {
	tests := []struct {
		name           string
		instance       string
		expected       string
		exptectedError error
	}{
		{
			name:           "valid instance",
			instance:       "1",
			expected:       "cb94950d7f03fff362cc44dca908c90e",
			exptectedError: nil,
		},
		{
			name:           "invalid instance",
			instance:       "abcd",
			expected:       "042ede2b02baf9c1219645633a221857",
			exptectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := NewInstanceID()
			assert.NotEqual(t, "", test.expected, res)
			assert.Equal(t, test.exptectedError, err)
		})
	}
}

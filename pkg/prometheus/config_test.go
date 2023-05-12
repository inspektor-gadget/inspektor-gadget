// Copyright 2023 The Inspektor Gadget authors
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

package prometheus

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseConfig(t *testing.T) {
	type testDefinition struct {
		name        string
		input       *Config
		expectedErr bool
	}

	tests := []testDefinition{
		{
			name: "all_good",
			input: &Config{
				MetricsName: "all_good",
				Metrics: []Metric{
					{
						Name:     "name",
						Category: "category",
						Gadget:   "gadget",
						Type:     "type",
					},
				},
			},
			expectedErr: false,
		},
		{
			name: "no_metrics",
			input: &Config{
				Metrics: nil,
			},
			expectedErr: true,
		},
		{
			name: "missing_metrics_name",
			input: &Config{
				MetricsName: "missing_metrics_name",
				Metrics: []Metric{
					{
						Name:     "",
						Category: "category",
						Gadget:   "gadget",
						Type:     "type",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "missing_metrics_category",
			input: &Config{
				MetricsName: "missing_metrics_category",
				Metrics: []Metric{
					{
						Name:     "name",
						Category: "",
						Gadget:   "gadget",
						Type:     "type",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "missing_metrics_gadget",
			input: &Config{
				MetricsName: "missing_metrics_gadget",
				Metrics: []Metric{
					{
						Name:     "name",
						Category: "category",
						Gadget:   "",
						Type:     "type",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "missing_metrics_type",
			input: &Config{
				MetricsName: "missing_metrics_type",
				Metrics: []Metric{
					{
						Name:     "name",
						Category: "category",
						Gadget:   "gadget",
						Type:     "",
					},
				},
			},
			expectedErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bytes, err := yaml.Marshal(test.input)
			require.Nil(t, err, "marshalling yaml")

			_, err = ParseConfig(bytes)
			if test.expectedErr {
				require.Error(t, err, "parsing config should return error")
			} else {
				require.Nil(t, err, "parsing config should return no error")
			}
		})
	}
}

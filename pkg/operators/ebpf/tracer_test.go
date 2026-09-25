// Copyright 2026 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

func TestResolvePerfBufferPages(t *testing.T) {
	instance := &ebpfInstance{
		logger: logger.DefaultLogger(),
	}

	tests := []struct {
		name          string
		annotations   map[string]string
		nilDataSource bool
		expected      int
	}{
		{
			name:          "nil datasource returns default",
			nilDataSource: true,
			expected:      gadgets.PerfBufferPages,
		},
		{
			name:        "missing annotation returns default",
			annotations: map[string]string{},
			expected:    gadgets.PerfBufferPages,
		},
		{
			name: "empty annotation value returns default",
			annotations: map[string]string{
				AnnotationTracerPerfBufferPages: "",
			},
			expected: gadgets.PerfBufferPages,
		},
		{
			name: "valid positive integer annotation returns custom value",
			annotations: map[string]string{
				AnnotationTracerPerfBufferPages: "128",
			},
			expected: 128,
		},
		{
			name: "zero value returns default",
			annotations: map[string]string{
				AnnotationTracerPerfBufferPages: "0",
			},
			expected: gadgets.PerfBufferPages,
		},
		{
			name: "negative value returns default",
			annotations: map[string]string{
				AnnotationTracerPerfBufferPages: "-10",
			},
			expected: gadgets.PerfBufferPages,
		},
		{
			name: "invalid non-integer string returns default",
			annotations: map[string]string{
				AnnotationTracerPerfBufferPages: "invalid",
			},
			expected: gadgets.PerfBufferPages,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ds datasource.DataSource
			if !tt.nilDataSource {
				var err error
				ds, err = datasource.New(datasource.TypeSingle, "test")
				require.NoError(t, err)
				for k, v := range tt.annotations {
					ds.AddAnnotation(k, v)
				}
			}

			pages := instance.resolvePerfBufferPages(ds)
			assert.Equal(t, tt.expected, pages)
		})
	}
}

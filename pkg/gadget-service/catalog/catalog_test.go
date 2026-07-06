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

package catalog

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		nilCfg  bool
		want    []Entry
		wantErr bool
	}{
		{
			name:   "nil config",
			nilCfg: true,
			want:   nil,
		},
		{
			name: "unset catalog",
			yaml: "events-buffer-length: 16384\n",
			want: nil,
		},
		{
			name: "empty catalog",
			yaml: "catalog: []\n",
			want: []Entry{},
		},
		{
			name: "single entry",
			yaml: `
catalog:
  - image: ghcr.io/inspektor-gadget/gadget/trace_open:latest
    name: trace_open
    description: Trace open() system calls
    tags:
      - file
      - trace
`,
			want: []Entry{
				{
					Image:       "ghcr.io/inspektor-gadget/gadget/trace_open:latest",
					Name:        "trace_open",
					Description: "Trace open() system calls",
					Tags:        []string{"file", "trace"},
				},
			},
		},
		{
			name: "multiple entries with minimal fields",
			yaml: `
catalog:
  - image: ghcr.io/inspektor-gadget/gadget/trace_open:latest
  - image: ghcr.io/inspektor-gadget/gadget/trace_exec:latest
    name: trace_exec
`,
			want: []Entry{
				{Image: "ghcr.io/inspektor-gadget/gadget/trace_open:latest"},
				{Image: "ghcr.io/inspektor-gadget/gadget/trace_exec:latest", Name: "trace_exec"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg *viper.Viper
			if !tt.nilCfg {
				cfg = viper.New()
				cfg.SetConfigType("yaml")
				require.NoError(t, cfg.ReadConfig(bytes.NewBufferString(tt.yaml)))
			}

			got, err := FromConfig(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

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

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestFilterCatalogByTags(t *testing.T) {
	t.Parallel()

	gadgets := []*api.CatalogGadget{
		{Gadget: "trace_open", Tags: []string{"file", "trace"}},
		{Gadget: "trace_dns", Tags: []string{"network", "dns", "trace"}},
		{Gadget: "top_file", Tags: []string{"file", "top"}},
		{Gadget: "no_tags"},
	}

	tests := []struct {
		name      string
		tags      []string
		wantNames []string
	}{
		{
			name:      "no filter returns all",
			tags:      nil,
			wantNames: []string{"trace_open", "trace_dns", "top_file", "no_tags"},
		},
		{
			name:      "single tag",
			tags:      []string{"file"},
			wantNames: []string{"trace_open", "top_file"},
		},
		{
			name:      "all tags must match",
			tags:      []string{"file", "trace"},
			wantNames: []string{"trace_open"},
		},
		{
			name:      "unknown tag matches nothing",
			tags:      []string{"does-not-exist"},
			wantNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := filterCatalogByTags(gadgets, tt.tags)
			var gotNames []string
			for _, g := range got {
				gotNames = append(gotNames, g.Gadget)
			}
			assert.Equal(t, tt.wantNames, gotNames)
		})
	}
}

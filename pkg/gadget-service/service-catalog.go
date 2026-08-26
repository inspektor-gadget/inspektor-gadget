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

package gadgetservice

import (
	"context"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/catalog"
)

// GetCatalog returns the server-side curated catalog of gadgets, read from the
// `catalog` configuration key. It is a discovery-only feature: it neither
// restricts which gadgets can run nor runs anything itself.
func (s *Service) GetCatalog(ctx context.Context, request *api.GetCatalogRequest) (*api.GetCatalogResponse, error) {
	entries, err := catalog.FromConfig(config.Config)
	if err != nil {
		return nil, fmt.Errorf("reading catalog from config: %w", err)
	}

	gadgets := make([]*api.CatalogGadget, 0, len(entries))
	for _, entry := range entries {
		gadgets = append(gadgets, &api.CatalogGadget{
			Gadget:      entry.Gadget,
			Description: entry.Description,
			Tags:        entry.Tags,
		})
	}

	return &api.GetCatalogResponse{Gadgets: gadgets}, nil
}

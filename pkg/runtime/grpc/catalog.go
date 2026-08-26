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

package grpcruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// GetCatalog returns the server-side curated catalog of gadgets. The catalog is
// derived from server configuration, which is shared across all nodes, so the
// results from every reachable target are merged and de-duplicated by image.
func (r *Runtime) GetCatalog(ctx context.Context, runtimeParams *params.Params) ([]*api.CatalogGadget, error) {
	targets, err := r.getTargets(ctx, runtimeParams)
	if err != nil {
		return nil, fmt.Errorf("getting targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found")
	}

	var mu sync.Mutex
	var gadgets []*api.CatalogGadget
	var errs []error

	wg := sync.WaitGroup{}
	for _, t := range targets {
		wg.Add(1)
		go func(target target) {
			defer wg.Done()
			conn, err := r.getConnFromTarget(ctx, runtimeParams, target)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("connecting to target %q: %w", target.node, err))
				mu.Unlock()
				return
			}
			defer conn.Close()

			client := api.NewGadgetCatalogManagerClient(conn)
			res, err := client.GetCatalog(ctx, &api.GetCatalogRequest{})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("getting catalog from target %q: %w", target.node, err))
				mu.Unlock()
				return
			}

			mu.Lock()
			gadgets = append(gadgets, res.Gadgets...)
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	if len(gadgets) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	slices.SortFunc(gadgets, func(a, b *api.CatalogGadget) int {
		return strings.Compare(a.Gadget, b.Gadget)
	})
	gadgets = slices.CompactFunc(gadgets, func(a, b *api.CatalogGadget) bool {
		return a.Gadget == b.Gadget
	})

	return gadgets, nil
}

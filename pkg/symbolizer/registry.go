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

package symbolizer

import (
	"sort"
	"sync"
)

var (
	registryLock sync.Mutex

	resolvers = []Resolver{}
)

func RegisterResolver(resolver Resolver) {
	registryLock.Lock()
	defer registryLock.Unlock()

	resolvers = append(resolvers, resolver)

	sort.Slice(resolvers, func(i, j int) bool {
		return resolvers[i].Priority() < resolvers[j].Priority()
	})
}

func newResolverInstances(options SymbolizerOptions) ([]ResolverInstance, error) {
	registryLock.Lock()
	defer registryLock.Unlock()

	instances := make([]ResolverInstance, 0, len(resolvers))
	for _, r := range resolvers {
		instance, err := r.NewInstance(options)
		if err != nil {
			return nil, err
		}
		if instance != nil {
			instances = append(instances, instance)
		}
	}
	return instances, nil
}

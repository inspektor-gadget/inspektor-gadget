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

import "time"

type Resolver interface {
	// Priority tells in which order to call Resolve(). Lower values first.
	Priority() int

	NewInstance(SymbolizerOptions) (ResolverInstance, error)
}

type ResolverInstance interface {
	GetEbpfReplacements() map[string]interface{}
	Resolve(task Task, stackQueries []StackItemQuery, stackResponses []StackItemResponse) error
	IsPruningNeeded() bool
	PruneOldObjects(now time.Time, ttl time.Duration)
}

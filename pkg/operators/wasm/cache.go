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

package wasm

import (
	"context"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
)

const cacheRefreshInterval = time.Minute

// compilationCache is a cache for the wasm compilation based on wazero.CompilationCache.
type compilationCache struct {
	cache       wazero.CompilationCache
	refreshTime time.Time
	refreshMu   sync.Mutex
}

func newCompilationCache() *compilationCache {
	return &compilationCache{
		cache:       wazero.NewCompilationCache(),
		refreshTime: time.Now(),
	}
}

func (c *compilationCache) refreshCache() {
	if time.Since(c.refreshTime) < cacheRefreshInterval {
		return
	}

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	if c.cache != nil {
		c.cache.Close(context.Background())
	}
	c.cache = wazero.NewCompilationCache()
	c.refreshTime = time.Now()
}

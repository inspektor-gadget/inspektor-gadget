// Copyright 2024 The Inspektor Gadget authors
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

package cachedmap

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultTestTTL = 2 * time.Second

func TestNewCachedMap(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	require.NotNil(t, cache)
	t.Cleanup(func() {
		cache.Close()
	})

	assert.Len(t, cache.current, 0)
	assert.Len(t, cache.old, 0)
}

func TestResourceCacheAdd(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	t.Cleanup(func() {
		cache.Close()
	})

	key := 1
	value := "value"
	cache.Add(key, value)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value, cache.current[key])
}

func TestResourceCacheOverwrite(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	t.Cleanup(func() {
		cache.Close()
	})

	key := 1
	value := "value"
	cache.Add(key, value)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value, cache.current[key])

	value2 := "value2"
	cache.Add(key, value2)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value2, cache.current[key])
}

func TestResourceCacheRemove(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	t.Cleanup(func() {
		cache.Close()
	})

	key := 1
	value := "value"
	cache.Add(key, value)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value, cache.current[key])

	cache.Remove(key)
	assert.Len(t, cache.current, 0)
	assert.Len(t, cache.old, 1)
	assert.Equal(t, value, cache.old[key].obj)
}

func TestResourceCachePruneOldObjects(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	t.Cleanup(func() {
		cache.Close()
	})

	key := 1
	value := "value"
	cache.Add(key, value)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value, cache.current[key])

	cache.Remove(key)
	assert.Len(t, cache.current, 0)
	assert.Len(t, cache.old, 1)
	assert.Equal(t, value, cache.old[key].obj)

	// Manually subtract the TTL from the timestamp
	temp := cache.old[key]
	temp.deletionTimestamp = temp.deletionTimestamp.Add(-defaultTestTTL)
	cache.old[key] = temp
	cache.pruneOldObjects()
	assert.Len(t, cache.current, 0)
	assert.Len(t, cache.old, 0)
}

func TestResourceCacheValues(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	t.Cleanup(func() {
		cache.Close()
	})

	key := 1
	value := "value"
	cache.Add(key, value)
	sliceFromCurrent := cache.Values()
	cache.Remove(key)
	sliceFromOld := cache.Values()

	// Manually subtract the TTL from the timestamp
	temp := cache.old[key]
	temp.deletionTimestamp = temp.deletionTimestamp.Add(-defaultTestTTL)
	cache.old[key] = temp
	cache.pruneOldObjects()

	sliceAfterPrune := cache.Values()

	require.Len(t, sliceFromCurrent, 1)
	require.Len(t, sliceFromOld, 1)
	assert.Equal(t, value, sliceFromCurrent[0])
	assert.Equal(t, value, sliceFromOld[0])
	assert.Len(t, sliceAfterPrune, 0)
}

func TestResourceCacheGet(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])
	t.Cleanup(func() {
		cache.Close()
	})

	key := 1
	value := "value"
	cache.Add(key, value)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value, cache.current[key])

	objFromCache, found := cache.Get(key)
	require.True(t, found)
	assert.Equal(t, value, objFromCache)
}

func TestResourceCacheGetNotFound(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])

	key := 1
	value := "value"
	cache.Add(key, value)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value, cache.current[key])

	_, found := cache.Get(2)
	assert.False(t, found)
}

func TestResourceCacheGetCmp(t *testing.T) {
	t.Parallel()

	cache := NewCachedMap[int, string](defaultTestTTL).(*cachedMap[int, string])

	key1 := 1
	value1 := "value1"
	cache.Add(key1, value1)
	assert.Len(t, cache.current, 1)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value1, cache.current[key1])

	key2 := 2
	value2 := "value2"
	cache.Add(key2, value2)
	assert.Len(t, cache.current, 2)
	assert.Len(t, cache.old, 0)
	assert.Equal(t, value2, cache.current[key2])

	objFromCache, found := cache.GetCmp(func(obj string) bool {
		return strings.HasSuffix(obj, "2")
	})
	require.True(t, found)
	assert.Equal(t, value2, objFromCache)
}

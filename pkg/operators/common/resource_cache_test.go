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

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewResourceCache(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)
	assert.Equal(t, 0, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	locked := cache.TryLock()
	assert.True(t, locked)
	if locked {
		cache.Unlock()
	}
}

func TestResourceCacheAdd(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])
}

func TestResourceCacheOverwrite(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])

	obj2 := &metav1.ObjectMeta{Name: key}
	cache.Add(obj2)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj2, *cache.current[key])
}

func TestResourceCacheRemove(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])

	cache.Remove(obj)
	assert.Equal(t, 0, len(cache.current))
	assert.Equal(t, 1, len(cache.old))
	assert.Equal(t, *obj, *cache.old[key].obj)
}

func TestResourceCachePruneOldObjects(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])

	cache.Remove(obj)
	assert.Equal(t, 0, len(cache.current))
	assert.Equal(t, 1, len(cache.old))
	assert.Equal(t, *obj, *cache.old[key].obj)

	// Manually subtract the TTL from the timestamp
	temp := cache.old[key]
	temp.deletionTimestamp = temp.deletionTimestamp.Add(-oldObjectTTL)
	cache.old[key] = temp
	cache.PruneOldObjects()
	assert.Equal(t, 0, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
}

func TestResourceCacheToSlice(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	sliceFromCurrent := cache.ToSlice()
	cache.Remove(obj)
	sliceFromOld := cache.ToSlice()

	// Manually subtract the TTL from the timestamp
	temp := cache.old[key]
	temp.deletionTimestamp = temp.deletionTimestamp.Add(-oldObjectTTL)
	cache.old[key] = temp
	cache.PruneOldObjects()

	sliceAfterPrune := cache.ToSlice()

	require.Equal(t, 1, len(sliceFromCurrent))
	require.Equal(t, 1, len(sliceFromOld))
	assert.Equal(t, *obj, *sliceFromCurrent[0])
	assert.Equal(t, *obj, *sliceFromOld[0])
	assert.Equal(t, 0, len(sliceAfterPrune))
}

func TestResourceCacheGet(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])

	objFromCache := cache.Get(key)
	require.NotNil(t, objFromCache)
	assert.Equal(t, *obj, *objFromCache)
}

func TestResourceCacheGetNotFound(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)

	key := "key"
	obj := &metav1.ObjectMeta{Name: key}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])

	objFromCache := cache.Get("notfound")
	assert.Nil(t, objFromCache)
}

func TestResourceCacheGetCmp(t *testing.T) {
	t.Parallel()

	cache := newResourceCache[metav1.ObjectMeta]()
	require.NotNil(t, cache)

	key := "key"
	labelKey := "foo"
	labelValue := "bar"
	obj := &metav1.ObjectMeta{Name: key, Labels: map[string]string{labelKey: labelValue}}
	cache.Add(obj)
	assert.Equal(t, 1, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj, *cache.current[key])

	key2 := "key2"
	labelKey2 := "foo2"
	labelValue2 := "bar2"
	obj2 := &metav1.ObjectMeta{Name: key2, Labels: map[string]string{labelKey2: labelValue2}}
	cache.Add(obj2)
	assert.Equal(t, 2, len(cache.current))
	assert.Equal(t, 0, len(cache.old))
	assert.Equal(t, *obj2, *cache.current[key2])

	objFromCache := cache.GetCmp(func(obj *metav1.ObjectMeta) bool {
		return obj.Labels[labelKey] == labelValue
	})
	require.NotNil(t, objFromCache)
	assert.Equal(t, *obj, *objFromCache)
}

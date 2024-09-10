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

// Package cachedmap provides a CachedMap which functions as a map with a TTL
// for old entries. So after an entry is "removed" from the map its value is still
// available for a certain amount of time.
package cachedmap

import (
	"sync"
	"time"
)

type oldResource[T any] struct {
	deletionTimestamp time.Time
	obj               T
}

type CachedMap[Key comparable, T any] interface {
	Clear()
	Add(key Key, obj T)
	Remove(key Key)
	Keys() []Key
	Values() []T
	Get(key Key) (T, bool)
	GetCmp(cmp func(T) bool) (T, bool)
	// Close stops the background goroutine that prunes old entries
	Close()
}

type cachedMap[Key comparable, T any] struct {
	sync.RWMutex
	current     map[Key]T
	old         map[Key]oldResource[T]
	oldEntryTTL time.Duration
	exit        chan struct{}
}

// NewCachedMap creates a new CachedMap with the given oldEntryTTL
// The old entries will be deleted between oldEntryTTL and 2*oldEntryTTL
func NewCachedMap[Key comparable, T any](oldEntryTTL time.Duration) CachedMap[Key, T] {
	cm := &cachedMap[Key, T]{
		current:     make(map[Key]T),
		old:         make(map[Key]oldResource[T]),
		oldEntryTTL: oldEntryTTL,
		exit:        make(chan struct{}),
	}
	go cm.pruneLoop()
	return cm
}

func (c *cachedMap[Key, T]) Close() {
	close(c.exit)
	c.Clear()
}

func (c *cachedMap[Key, T]) Clear() {
	c.Lock()
	defer c.Unlock()
	c.current = make(map[Key]T)
	c.old = make(map[Key]oldResource[T])
}

func (c *cachedMap[Key, T]) Add(key Key, obj T) {
	c.Lock()
	defer c.Unlock()
	c.current[key] = obj
	delete(c.old, key)
}

func (c *cachedMap[Key, T]) Remove(key Key) {
	c.Lock()
	defer c.Unlock()
	oldObj, ok := c.current[key]
	if ok {
		delete(c.current, key)
		c.old[key] = oldResource[T]{deletionTimestamp: time.Now(), obj: oldObj}
	}
}

func (c *cachedMap[Key, T]) pruneLoop() {
	ticker := time.NewTicker(c.oldEntryTTL)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.pruneOldObjects()
		case <-c.exit:
			return
		}
	}
}

func (c *cachedMap[Key, T]) pruneOldObjects() {
	c.Lock()
	defer c.Unlock()
	now := time.Now()
	for key, oldObj := range c.old {
		if now.Sub(oldObj.deletionTimestamp) > c.oldEntryTTL {
			delete(c.old, key)
		}
	}
}

func (c *cachedMap[Key, T]) Keys() []Key {
	c.RLock()
	defer c.RUnlock()

	keys := make([]Key, 0, len(c.current)+len(c.old))
	for key := range c.current {
		keys = append(keys, key)
	}
	for oldKey := range c.old {
		if _, ok := c.current[oldKey]; !ok {
			keys = append(keys, oldKey)
		}
	}
	return keys
}

func (c *cachedMap[Key, T]) Values() []T {
	c.RLock()
	defer c.RUnlock()

	objs := make([]T, 0, len(c.current)+len(c.old))
	for _, obj := range c.current {
		objs = append(objs, obj)
	}
	for oldKey, oldObj := range c.old {
		if _, ok := c.current[oldKey]; !ok {
			objs = append(objs, oldObj.obj)
		}
	}
	return objs
}

func (c *cachedMap[Key, T]) Get(key Key) (T, bool) {
	c.RLock()
	defer c.RUnlock()

	if obj, ok := c.current[key]; ok {
		return obj, true
	}
	if oldObj, ok := c.old[key]; ok {
		return oldObj.obj, true
	}

	var zeroValue T
	return zeroValue, false
}

// GetCmp returns the first object for which the cmp function returns true
// The cmp function is applied to both current and old objects until a match is found
// This is an expensive operation and should be used with caution
func (c *cachedMap[Key, T]) GetCmp(cmp func(T) bool) (T, bool) {
	c.RLock()
	defer c.RUnlock()

	for _, obj := range c.current {
		if cmp(obj) {
			return obj, true
		}
	}
	for _, oldObj := range c.old {
		if cmp(oldObj.obj) {
			return oldObj.obj, true
		}
	}
	var zeroValue T
	return zeroValue, false
}

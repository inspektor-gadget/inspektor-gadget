// Copyright 2022 The Inspektor Gadget authors
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

package snapshotcombiner

import (
	"sync"
	"time"
)

// Stats contains the status of the SnapshotCombiner when calling GetSnapshots()
type Stats struct {
	Epochs           int // Number of calls to GetSnapshots()
	CurrentSnapshots int // Number of wrappedSnapshots that have been updated since the previous call to GetSnapshots()
	ExpiredSnapshots int // Number of wrappedSnapshots that have a ttl of 0
	TotalSnapshots   int // Number of wrappedSnapshots known
}

type snapshotWrapper[T any] struct {
	snapshot   []*T
	ttl        int
	count      int
	lastUpdate time.Time
}

type SnapshotCombiner[T any] struct {
	lock             sync.Mutex
	defaultTTL       int
	wrappedSnapshots map[string]*snapshotWrapper[T]
	epoch            int
}

// NewSnapshotCombiner creates a new wrappedSnapshots combiner that stores structs of type T using a key. Each key is
// given a time-to-live (ttl) and only valid for ttl calls of GetSnapshots(). Whenever a key is refreshed using
// AddSnapshot(), the ttl will be reset to the initial value.
func NewSnapshotCombiner[T any](ttl int) *SnapshotCombiner[T] {
	return &SnapshotCombiner[T]{
		defaultTTL:       ttl,
		wrappedSnapshots: make(map[string]*snapshotWrapper[T]),
	}
}

// AddSnapshot adds the given snapshot to the given key (e.g. a node name) and set its ttl to the defaultTTL of the
// SnapshotCombiner
func (sc *SnapshotCombiner[T]) AddSnapshot(key string, snapshot []*T) {
	now := time.Now()

	sc.lock.Lock()
	defer sc.lock.Unlock()

	if entry, ok := sc.wrappedSnapshots[key]; ok {
		entry.snapshot = snapshot
		entry.ttl = sc.defaultTTL
		entry.count++
		entry.lastUpdate = now
		return
	}
	sc.wrappedSnapshots[key] = &snapshotWrapper[T]{
		snapshot:   snapshot,
		ttl:        sc.defaultTTL,
		count:      1,
		lastUpdate: now,
	}
}

// GetSnapshots combines all stored wrappedSnapshots from all keys and decreases each keys defaultTTL by one.
// If the ttl of an entry is less than zero, it will not be returned anymore.
func (sc *SnapshotCombiner[T]) GetSnapshots() ([]*T, Stats) {
	sc.lock.Lock()
	defer sc.lock.Unlock()

	// increase epoch
	sc.epoch++

	stats := Stats{
		Epochs: sc.epoch,
	}

	result := make([]*T, 0, len(sc.wrappedSnapshots))
	for _, wrapper := range sc.wrappedSnapshots {
		if wrapper.ttl == sc.defaultTTL {
			stats.CurrentSnapshots++
		}
		if wrapper.ttl > 0 {
			result = append(result, wrapper.snapshot...)
			wrapper.ttl--
		} else {
			stats.ExpiredSnapshots++
		}
	}

	stats.TotalSnapshots = len(sc.wrappedSnapshots)

	return result, stats
}

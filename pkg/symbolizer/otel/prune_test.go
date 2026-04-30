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

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPruneCorrelationMap_BasicCleanup(t *testing.T) {
	o := newTestInstance()

	// Simulate: correlation IDs 100, 200, 300 are in the Go map.
	o.correlationMap[100] = makeFrames("func_a")
	o.correlationMap[200] = makeFrames("func_b")
	o.correlationMap[300] = makeFrames("func_c")

	// BPF map has 100 and 300, but not 200 (simulating LRU eviction).
	activeBPF := map[uint64]bool{100: true, 300: true}

	// First prune: ID 200 should become a candidate, not deleted yet.
	o.pruneCorrelationMap(activeBPF)
	assert.Contains(t, o.correlationMap, uint64(100))
	assert.Contains(t, o.correlationMap, uint64(200), "should not delete on first prune")
	assert.Contains(t, o.correlationMap, uint64(300))
	assert.True(t, o.pruneCandidate[200])

	// Second prune: ID 200 still absent → deleted.
	o.pruneCorrelationMap(activeBPF)
	assert.Contains(t, o.correlationMap, uint64(100))
	assert.NotContains(t, o.correlationMap, uint64(200), "should delete after two prune cycles")
	assert.Contains(t, o.correlationMap, uint64(300))
}

func TestPruneCorrelationMap_CandidateReappears(t *testing.T) {
	o := newTestInstance()

	o.correlationMap[100] = makeFrames("func_a")

	// First prune: 100 absent from BPF → becomes candidate.
	o.pruneCorrelationMap(map[uint64]bool{})
	assert.True(t, o.pruneCandidate[100])

	// Re-appears in BPF before second prune.
	o.pruneCorrelationMap(map[uint64]bool{100: true})
	assert.Contains(t, o.correlationMap, uint64(100),
		"should not delete if ID reappeared in BPF map")
}

func TestPruneCorrelationMap_EmptyBPFMap(t *testing.T) {
	o := newTestInstance()

	o.correlationMap[100] = makeFrames("func_a")
	o.correlationMap[200] = makeFrames("func_b")

	// First prune: all become candidates.
	o.pruneCorrelationMap(map[uint64]bool{})
	assert.Len(t, o.correlationMap, 2, "should not delete on first prune")
	assert.Len(t, o.pruneCandidate, 2)

	// Second prune: all deleted.
	o.pruneCorrelationMap(map[uint64]bool{})
	assert.Empty(t, o.correlationMap, "all entries should be pruned")
	assert.Empty(t, o.pruneCandidate)
}

func TestPruneCorrelationMap_EmptyGoMap(t *testing.T) {
	o := newTestInstance()

	// Nothing to prune — should be a no-op.
	o.pruneCorrelationMap(map[uint64]bool{100: true})
	assert.Empty(t, o.correlationMap)
	assert.Empty(t, o.pruneCandidate)
}

func TestPruneOldObjects_NilTracer(t *testing.T) {
	o := newTestInstance()
	o.correlationMap[100] = makeFrames("func_a")

	// Should be a no-op, not panic.
	o.PruneOldObjects(time.Now(), time.Minute)
	assert.Contains(t, o.correlationMap, uint64(100))
}

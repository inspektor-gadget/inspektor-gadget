// Copyright 2022-2023 The Inspektor Gadget authors
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSnapshotCombiner(t *testing.T) {
	ttl := 2
	sc := NewSnapshotCombiner[int](ttl)

	type testRun struct {
		Name            string
		IntervalStats   map[string][]*int
		ExpectedEntries int
	}

	data1 := 1
	data2 := 2
	data3 := 3
	data4 := 4

	testSteps := []testRun{
		{
			Name: "No snapshots sent, should return an empty result",
		},
		{
			Name: "one node sends a snapshot",
			IntervalStats: map[string][]*int{
				"node1": {&data1},
			},
			ExpectedEntries: 1,
		},
		{
			Name:            "no node sends snapshots, old snapshots should still be there",
			ExpectedEntries: 1,
		},
		{
			Name: "no node sends snapshots, old snapshots should have gotten deleted",
		},

		{
			Name: "one node sends a snapshot",
			IntervalStats: map[string][]*int{
				"node1": {&data1},
			},
			ExpectedEntries: 1,
		},
		{
			Name: "same node sends a snapshot (defaultTTL refresh), still one result",
			IntervalStats: map[string][]*int{
				"node1": {&data1},
			},
			ExpectedEntries: 1,
		},
		{
			Name:            "no node sends snapshots, old snapshots should still be there",
			ExpectedEntries: 1,
		},
		{
			Name: "no node sends snapshots, old snapshots should have gotten deleted",
		},

		{
			Name: "two nodes send snapshots with two entries each",
			IntervalStats: map[string][]*int{
				"node1": {&data1, &data2},
				"node2": {&data3, &data4},
			},
			ExpectedEntries: 4,
		},
		{
			Name: "only one of the two nodes sends a snapshot in the next interval, still all 4 entries should show",
			IntervalStats: map[string][]*int{
				"node1": {&data1, &data2},
			},
			ExpectedEntries: 4,
		},
		{
			Name: "still only one of the two nodes sends a snapshot, two entries from node2 should be lost now",
			IntervalStats: map[string][]*int{
				"node1": {&data1, &data2},
			},
			ExpectedEntries: 2,
		},
	}

	for _, step := range testSteps {
		for nodeName, nodeStats := range step.IntervalStats {
			sc.AddSnapshot(nodeName, nodeStats)
		}
		res, _ := sc.GetSnapshots()
		require.Len(t, res, step.ExpectedEntries, "expected %d, got %d", step.ExpectedEntries, len(res))
	}
}

// TestSnapshotCombiner_ExpiredEntriesAreDeleted verifies that GetSnapshots() removes
// entries whose TTL has reached zero from the internal map, preventing memory leaks
// in long-running deployments with high node churn.
func TestSnapshotCombiner_ExpiredEntriesAreDeleted(t *testing.T) {
	ttl := 1
	sc := NewSnapshotCombiner[int](ttl)

	val := 42
	sc.AddSnapshot("node1", []*int{&val})

	// First call: TTL goes from 1 to 0, entry is still returned.
	res, stats := sc.GetSnapshots()
	require.Len(t, res, 1, "expected snapshot to be present on first call")
	require.Equal(t, 1, stats.TotalSnapshots, "map should still hold the entry after first call")

	// Second call: TTL is 0, entry must be excluded from results AND deleted from the map.
	res, stats = sc.GetSnapshots()
	require.Len(t, res, 0, "expected no snapshot after TTL expired")
	require.Equal(t, 0, stats.TotalSnapshots, "expired entry should have been deleted from the internal map")
	require.Equal(t, 1, stats.ExpiredSnapshots, "expired snapshot count should reflect the removed entry")
}


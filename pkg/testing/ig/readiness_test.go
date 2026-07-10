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

package ig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Realistic logrus-formatted stderr lines (non-TTY text formatter).
const (
	// Bare marker emitted by the local runtime, and also by the client itself for the gRPC
	// runtime (LoadGadgetInfo with run=true). logrus does not quote the message as it has no
	// spaces (verified against real `ig run -v` output).
	bareMarker = `time="2026-07-08T12:00:00Z" level=debug msg=running...`
	// Node-prefixed markers forwarded from remote nodes by the gRPC runtime
	// (fmt.Sprintf("%-20s | %s", node, "running...")).
	nodeAMarker = `time="2026-07-08T12:00:01Z" level=debug msg="gke-node-a           | running..."`
	nodeBMarker = `time="2026-07-08T12:00:02Z" level=debug msg="gke-node-b           | running..."`
	// Client-side "dispatched to node" lines (one per target, see runGadgetOnTargets). These
	// tell the gate how many node readiness markers to expect.
	dispatchAMarker = `time="2026-07-08T12:00:00Z" level=debug msg="running gadget on node \"gke-node-a\""`
	dispatchBMarker = `time="2026-07-08T12:00:00Z" level=debug msg="running gadget on node \"gke-node-b\""`
)

func TestParseReadyNode(t *testing.T) {
	nA, isNodeA := parseReadyNode(nodeAMarker)
	assert.True(t, isNodeA)
	assert.Equal(t, "gke-node-a", nA)

	nB, isNodeB := parseReadyNode(nodeBMarker)
	assert.True(t, isNodeB)
	assert.Equal(t, "gke-node-b", nB)

	// Distinct nodes yield distinct identifiers; the same line is stable.
	assert.NotEqual(t, nA, nB)
	nA2, _ := parseReadyNode(nodeAMarker)
	assert.Equal(t, nA, nA2)

	// A bare marker is not a node marker.
	_, isNode := parseReadyNode(bareMarker)
	assert.False(t, isNode)
}

func TestReadinessWatcher_LocalMode(t *testing.T) {
	w := newReadinessWatcher()

	// Not ready before any marker.
	assert.False(t, w.ready(false))

	// A dispatch line does not make the local runtime ready.
	w.observe(dispatchAMarker)
	assert.False(t, w.ready(false))

	// A bare marker makes it ready in local (non-node) mode.
	w.observe(bareMarker)
	assert.True(t, w.ready(false))
}

func TestReadinessWatcher_NodeMode(t *testing.T) {
	w := newReadinessWatcher()

	// The client's own bare marker must NOT count towards node readiness, and with no
	// dispatch seen yet the gate is not ready.
	w.observe(bareMarker)
	assert.False(t, w.ready(true))

	// Two nodes are dispatched to.
	w.observe(dispatchAMarker)
	w.observe(dispatchBMarker)
	assert.False(t, w.ready(true))

	// First node ready: still waiting for the second.
	w.observe(nodeAMarker)
	assert.False(t, w.ready(true))

	// Duplicate marker from the same node must not advance readiness.
	w.observe(nodeAMarker)
	assert.False(t, w.ready(true))

	// Second distinct node makes all dispatched nodes ready.
	w.observe(nodeBMarker)
	assert.True(t, w.ready(true))
}

func TestReadinessWatcher_NodeReadyNeedsDispatch(t *testing.T) {
	// A node marker without a preceding dispatch line (which cannot happen in practice, since a
	// node is always dispatched before it reports ready) must not by itself satisfy the gate:
	// readiness requires at least one dispatched node.
	w := newReadinessWatcher()
	w.observe(nodeAMarker)
	assert.False(t, w.ready(true))
}

func TestReadinessWatcher_SomeReady(t *testing.T) {
	// Node mode: only a node marker counts as "some ready", not the client's bare marker or a
	// dispatch line.
	w := newReadinessWatcher()
	assert.False(t, w.someReady(true))
	w.observe(bareMarker)
	w.observe(dispatchAMarker)
	assert.False(t, w.someReady(true))
	w.observe(nodeAMarker)
	assert.True(t, w.someReady(true))

	// Local mode: the bare marker is enough.
	wl := newReadinessWatcher()
	assert.False(t, wl.someReady(false))
	wl.observe(bareMarker)
	assert.True(t, wl.someReady(false))
}

func TestReadinessWatcher_UpdatedSignal(t *testing.T) {
	w := newReadinessWatcher()

	w.observe(nodeAMarker)
	select {
	case <-w.updated:
	default:
		t.Fatal("expected an update signal after a new node marker")
	}

	// A duplicate must not produce a new signal.
	w.observe(nodeAMarker)
	select {
	case <-w.updated:
		t.Fatal("did not expect an update signal for a duplicate marker")
	default:
	}
}

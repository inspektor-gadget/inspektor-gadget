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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	// readinessMarker is the debug message the gadget logs right after all operators
	// (including the eBPF programs) have been started. Waiting for it lets the harness run
	// the workload only once the gadget is actually capturing, instead of betting on a fixed
	// sleep. It is emitted by pkg/gadget-context (see run.go and gadget-context.go); keep this
	// string in sync with those log messages.
	//
	// Beyond this string, the gate also relies on two stable behaviours of the CLI stderr:
	// the gRPC runtime forwards remote-node logs prefixed with "<node> | " as the raw message
	// (pkg/runtime/grpc, see parseReadyNode), and logrus uses its non-TTY key=value format
	// ("level=debug", quoted msg). If either changes, node discrimination or debug filtering
	// here must be updated accordingly.
	readinessMarker = "running..."

	// nodeMarkerSep identifies a readiness marker that was forwarded from a remote node by the
	// gRPC runtime, which prefixes forwarded logs with "<node> | " (see pkg/runtime/grpc).
	nodeMarkerSep = "| " + readinessMarker

	// dispatchMarker is the debug message the gRPC runtime (kubectl-gadget) logs once for each
	// node it runs the gadget on, before that node starts (see runGadgetOnTargets in
	// pkg/runtime/grpc/oci.go). Counting these tells the gate how many nodes to expect a
	// readiness marker from, honouring --node scoping, without querying the cluster. A node is
	// always dispatched before it can report ready, so "all dispatched nodes are ready" is
	// reached exactly when the number of distinct ready nodes equals the dispatched count.
	dispatchMarker = "running gadget on node "

	// readinessTimeout bounds how long the gate waits for the readiness marker. It only needs to
	// exceed the worst-case cold start (first-run OCI image pull plus load/attach on a slow
	// node; heavier gadgets that bundle a WASM module take noticeably longer, especially on the
	// multi-node minikube runners where the "nodes" share one host). A gadget that fails to
	// start exits and is caught immediately by exit tracking (see WaitForReady), so this can be
	// generous without making failing tests hang. If it expires with at least one instance
	// capturing, the gate proceeds anyway.
	readinessTimeout = 60 * time.Second
)

// readinessWatcher tracks gadget readiness on stderr. For the gRPC runtime (kubectl-gadget) it
// counts the nodes the gadget was dispatched to and the distinct nodes that reported ready (each
// via a node-prefixed marker); for the local runtime (ig) a single bare marker is expected.
type readinessWatcher struct {
	mu         sync.Mutex
	dispatched int
	nodes      map[string]struct{}
	bareSeen   bool
	updated    chan struct{}
}

func newReadinessWatcher() *readinessWatcher {
	return &readinessWatcher{
		nodes:   make(map[string]struct{}),
		updated: make(chan struct{}, 1),
	}
}

// observe is invoked with each stderr line while the gadget is running.
func (w *readinessWatcher) observe(line string) {
	var changed bool

	switch {
	case strings.Contains(line, dispatchMarker):
		w.mu.Lock()
		w.dispatched++
		changed = true
		w.mu.Unlock()
	case strings.Contains(line, readinessMarker):
		node, isNode := parseReadyNode(line)
		w.mu.Lock()
		if isNode {
			if _, ok := w.nodes[node]; !ok {
				w.nodes[node] = struct{}{}
				changed = true
			}
		} else if !w.bareSeen {
			w.bareSeen = true
			changed = true
		}
		w.mu.Unlock()
	}

	if changed {
		select {
		case w.updated <- struct{}{}:
		default:
		}
	}
}

// ready reports whether every node the gadget was dispatched to has reported ready (gRPC), or a
// bare marker was seen (local). Because a node is always dispatched before it can report ready,
// this is true exactly when all expected nodes are capturing.
//
// This compares a running count of dispatched nodes against the ready set, which is safe because
// dispatch lines and readiness markers arrive on the same, in-order stderr stream: a node's
// dispatch line is logged client-side within microseconds of the run starting (in the goroutine
// spawn loop of runGadgetOnTargets, pkg/runtime/grpc/oci.go), while its readiness marker is only
// produced after a full gRPC round trip plus image pull/load/attach (seconds later, forwarded
// from the node). So by the time observe() sees any readiness marker, every dispatch line that
// precedes it in the stream has already been counted; the running dispatched count is therefore
// already final. The dispatch line is logged exactly once per target (no retry), so counting
// occurrences equals the node count. A hypothetical extra or missing marker cannot cause an early
// pass: it would only delay the gate until the graceful timeout in WaitForReady.
func (w *readinessWatcher) ready(nodeMode bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if nodeMode {
		return w.dispatched >= 1 && len(w.nodes) >= w.dispatched
	}
	return w.bareSeen
}

// someReady reports whether at least one instance has reported ready. It's used to decide
// whether to proceed (with a warning) when not all dispatched nodes are ready before the
// timeout, so a lagging or unreachable node cannot fail an otherwise-capturing run.
func (w *readinessWatcher) someReady(nodeMode bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if nodeMode {
		return len(w.nodes) >= 1
	}
	return w.bareSeen
}

func (w *readinessWatcher) summary() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprintf("%d/%d node(s) ready, bare marker seen: %v", len(w.nodes), w.dispatched, w.bareSeen)
}

// parseReadyNode extracts a distinct node identifier from a forwarded, node-prefixed readiness
// marker. It returns (_, false) for a bare (non-forwarded) marker. The gRPC runtime forwards
// remote logs as `fmt.Sprintf("%-20s | %s", node, msg)`, which the client re-logs (logrus
// key=value, non-TTY) as `... msg="<node>          | running..."`.
func parseReadyNode(line string) (string, bool) {
	i := strings.Index(line, nodeMarkerSep)
	if i < 0 {
		return "", false
	}
	// Everything up to the separator ends with the padded node name; trim the "%-20s" padding.
	prefix := strings.TrimRight(line[:i], " ")
	// The node name is the logrus message value, i.e. what follows the last `msg="`.
	if j := strings.LastIndex(prefix, `msg="`); j >= 0 {
		return prefix[j+len(`msg="`):], true
	}
	// Fallback: the last whitespace-separated token (node names contain no spaces).
	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return "", false
	}
	return fields[len(fields)-1], true
}

// enableReadinessGate configures the runner to detect the gadget readiness marker on stderr. It
// runs the gadget with "-v" so the marker is emitted and observes stderr live.
func (ig *runner) enableReadinessGate() {
	ig.waitReady = true
	ig.readyWatcher = newReadinessWatcher()
	ig.flags = append(ig.flags, "-v")
	ig.StdErrLineObserver = ig.readyWatcher.observe
	// Track the process exit so the gate can fail fast if the gadget exits before it becomes
	// ready (e.g. image pull, signature, eBPF load/verifier or capability errors), instead of
	// waiting for readinessTimeout.
	ig.TrackExit()
}

// WaitForReady blocks until the gadget has reported that it is running (and thus capturing) on
// all expected instances, or fails the test after readinessTimeout. It is a no-op when the
// readiness gate is not enabled.
func (ig *runner) WaitForReady(t *testing.T) {
	if !ig.waitReady || ig.readyWatcher == nil {
		return
	}

	nodeMode := utils.CurrentTestComponent == utils.KubectlGadgetTestComponent

	deadline := time.NewTimer(readinessTimeout)
	defer deadline.Stop()

	// exitCh fires if the gadget process exits before becoming ready (nil when exit tracking
	// is disabled, which blocks forever in the select and is thus a no-op).
	exitCh := ig.ExitCh()

	for {
		if ig.readyWatcher.ready(nodeMode) {
			t.Logf("[%s] gadget ready (%s)", ig.Name, ig.readyWatcher.summary())
			return
		}
		select {
		case <-ig.readyWatcher.updated:
		case <-exitCh:
			// The process exited before all instances reported ready. A StartAndStop gadget
			// must keep running to capture, so an early exit is always a failure; fail now
			// instead of waiting for the timeout. The deferred Stop() prints the gadget's
			// stderr (the actual error).
			if err := ig.ExitErr(); err != nil {
				t.Fatalf("[%s] gadget exited before it started capturing: %v (%s)",
					ig.Name, err, ig.readyWatcher.summary())
			}
			t.Fatalf("[%s] gadget exited before it started capturing (%s)",
				ig.Name, ig.readyWatcher.summary())
		case <-deadline.C:
			// If at least one instance is capturing, proceed rather than failing: a lagging
			// or unreachable node (or an over-counted "want") must not turn an otherwise
			// capturing run into a hard failure. Only fail if nothing became ready at all.
			if ig.readyWatcher.someReady(nodeMode) {
				t.Logf("[%s] gadget readiness timed out after %s; proceeding with partial readiness (%s)",
					ig.Name, readinessTimeout, ig.readyWatcher.summary())
				return
			}
			t.Fatalf("[%s] gadget did not become ready within %s (%s)",
				ig.Name, readinessTimeout, ig.readyWatcher.summary())
		}
	}
}

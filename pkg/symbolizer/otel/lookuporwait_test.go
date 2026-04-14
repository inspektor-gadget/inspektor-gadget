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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"
)

// makeFrames creates a libpf.Frames slice with the given function names.
func makeFrames(names ...string) libpf.Frames {
	var frames libpf.Frames
	for _, name := range names {
		frame := libpf.Frame{
			FunctionName: libpf.Intern(name),
		}
		frames.Append(&frame)
	}
	return frames
}

// newTestInstance creates an otelResolverInstance suitable for unit
// testing lookupOrWait without starting the OTel eBPF profiler.
func newTestInstance() *otelResolverInstance {
	return &otelResolverInstance{
		correlationMap: make(map[uint64]libpf.Frames),
		waiters:        make(map[uint64]chan struct{}),
	}
}

// simulateTraceArrival mimics what traceReporter.reportTraceEvent does:
// inserts frames into correlationMap and wakes any waiters.
func simulateTraceArrival(o *otelResolverInstance, correlationID uint64, frames libpf.Frames) {
	o.mu.Lock()
	o.correlationMap[correlationID] = frames
	if ch, ok := o.waiters[correlationID]; ok {
		close(ch)
		delete(o.waiters, correlationID)
	}
	o.mu.Unlock()
}

// getBootTimeNs returns the current CLOCK_BOOTTIME in nanoseconds.
func getBootTimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func TestLookupOrWait_ImmediateHit(t *testing.T) {
	o := newTestInstance()
	expected := makeFrames("foo", "bar")
	o.correlationMap[42] = expected

	start := time.Now()
	frames, ok := o.lookupOrWait(42, 0)
	elapsed := time.Since(start)

	require.True(t, ok, "expected immediate hit")
	assert.Equal(t, len(expected), len(frames))
	assert.Less(t, elapsed, 10*time.Millisecond,
		"immediate hit should return without blocking")
}

func TestLookupOrWait_ChannelNotification(t *testing.T) {
	o := newTestInstance()
	expected := makeFrames("eat_apple", "eat_banana")

	var wg sync.WaitGroup
	var gotFrames libpf.Frames
	var gotOk bool

	wg.Add(1)
	go func() {
		defer wg.Done()
		gotFrames, gotOk = o.lookupOrWait(99, 0)
	}()

	// Give lookupOrWait time to register its waiter before delivering.
	time.Sleep(50 * time.Millisecond)
	simulateTraceArrival(o, 99, expected)

	wg.Wait()
	require.True(t, gotOk, "expected frames to arrive via channel")
	assert.Equal(t, len(expected), len(gotFrames))
	assert.Equal(t, "eat_apple", gotFrames[0].Value().FunctionName.String())
}

func TestLookupOrWait_Timeout(t *testing.T) {
	o := newTestInstance()

	start := time.Now()
	frames, ok := o.lookupOrWait(999, 0)
	elapsed := time.Since(start)

	assert.False(t, ok, "expected timeout (no frames)")
	assert.Nil(t, frames)
	// Should have waited approximately correlationTimeout (800ms).
	assert.Greater(t, elapsed, correlationTimeout-100*time.Millisecond,
		"should wait at least close to the full timeout")
	assert.Less(t, elapsed, correlationTimeout+200*time.Millisecond,
		"should not wait much longer than the timeout")
}

func TestLookupOrWait_AdaptiveTimeout_PastDeadline(t *testing.T) {
	o := newTestInstance()

	// Simulate an event that happened more than correlationTimeout ago.
	oldTimestamp := getBootTimeNs() - uint64(2*correlationTimeout)

	start := time.Now()
	_, ok := o.lookupOrWait(100, oldTimestamp)
	elapsed := time.Since(start)

	assert.False(t, ok, "expected no frames (past deadline)")
	assert.Less(t, elapsed, 100*time.Millisecond,
		"should return almost immediately when event is past deadline")
}

func TestLookupOrWait_AdaptiveTimeout_FutureTimestamp(t *testing.T) {
	o := newTestInstance()

	// Simulate a clock anomaly: event timestamp is in the future.
	futureTimestamp := getBootTimeNs() + uint64(10*time.Second)

	start := time.Now()
	_, ok := o.lookupOrWait(101, futureTimestamp)
	elapsed := time.Since(start)

	assert.False(t, ok, "expected no frames (clock anomaly)")
	assert.Less(t, elapsed, 100*time.Millisecond,
		"should return immediately on clock anomaly, not block")
}

func TestLookupOrWait_MultipleWaiters(t *testing.T) {
	o := newTestInstance()
	expected := makeFrames("shared_func")

	const numWaiters = 3
	var wg sync.WaitGroup
	results := make([]bool, numWaiters)

	for i := 0; i < numWaiters; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, ok := o.lookupOrWait(200, 0)
			results[idx] = ok
		}(i)
	}

	// Let all goroutines register as waiters.
	time.Sleep(50 * time.Millisecond)
	simulateTraceArrival(o, 200, expected)

	wg.Wait()
	for i, ok := range results {
		assert.True(t, ok, "waiter %d should have received frames", i)
	}
}

func TestLookupOrWait_AdaptiveTimeout_ReducesWait(t *testing.T) {
	o := newTestInstance()

	// Event happened 600ms ago — remaining timeout should be ~200ms.
	recentTimestamp := getBootTimeNs() - uint64(600*time.Millisecond)

	start := time.Now()
	_, ok := o.lookupOrWait(102, recentTimestamp)
	elapsed := time.Since(start)

	assert.False(t, ok, "expected timeout")
	// Should wait ~200ms (800ms - 600ms), not the full 800ms.
	assert.Less(t, elapsed, 500*time.Millisecond,
		"adaptive timeout should reduce the wait")
	assert.Greater(t, elapsed, 50*time.Millisecond,
		"should still wait some time")
}

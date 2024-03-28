// Copyright 2023 The Inspektor Gadget authors
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

package eventsorter

import (
	"sort"
	"sync"
	"time"
)

const (
	// defaultDelay is the time the event sorter should wait to see if
	// another event is coming with an earlier timestamp.
	//
	// Note: some tests have this code pattern:
	//         // Give some time for the tracer to capture the events
	//         time.Sleep(100 * time.Millisecond)
	//
	// defaultDelay should be smaller to make sure that the tests wait
	// enough time.
	defaultDelay = 50 * time.Millisecond
)

type scheduledCallback struct {
	// Timestamp is used to compare the timestamps of scheduled callback
	// with each others
	Timestamp uint64

	// AppendTime is the time when the scheduled callback was appended in
	// the event sorter
	AppendTime time.Time
	Callback   func()
}

type EventSorter struct {
	delay time.Duration

	ticker *time.Ticker
	done   chan bool
	closed bool

	mu                 sync.Mutex
	scheduledCallbacks []scheduledCallback
}

// EventSorterOption are options to pass to
// NewEventSorter using the functional option code pattern.
type EventSorterOption func(*EventSorter)

// NewEventSorter creates a new event sorter
func NewEventSorter(options ...EventSorterOption) *EventSorter {
	es := &EventSorter{
		delay:  defaultDelay,
		ticker: time.NewTicker(defaultDelay),
		done:   make(chan bool),
	}

	// Call functional options.
	for _, o := range options {
		o(es)
	}

	go es.run()
	return es
}

func WithCustomDelay(delay time.Duration) EventSorterOption {
	return func(es *EventSorter) {
		es.delay = delay
	}
}

func (es *EventSorter) Append(timestamp uint64, callback func()) {
	resetTicker := es.appendAtTime(timestamp, time.Now(), callback)
	if resetTicker {
		es.ticker.Reset(es.delay)
	}
}

func (es *EventSorter) appendAtTime(timestamp uint64, now time.Time, callback func()) bool {
	es.mu.Lock()
	defer es.mu.Unlock()

	es.scheduledCallbacks = append(es.scheduledCallbacks, scheduledCallback{
		Timestamp:  timestamp,
		AppendTime: now,
		Callback:   callback,
	})

	return len(es.scheduledCallbacks) == 1
}

// process checks callbacks that are due to be called in the right order.
//
// It is deterministic so it can be easily tested in unit tests. It does not
// call time.Now() or ticker.Reset() but let the caller do that.
//
// Returns when the next ticker should run, or zero if it should be disabled.
func (es *EventSorter) process(now time.Time) time.Duration {
	callNow := []scheduledCallback{}
	maxTimestamp := uint64(0)

	es.mu.Lock()
	// find maxTimestamp
	for i := len(es.scheduledCallbacks) - 1; i >= 0; i-- {
		if now.After(es.scheduledCallbacks[i].AppendTime.Add(es.delay)) {
			if maxTimestamp < es.scheduledCallbacks[i].Timestamp {
				maxTimestamp = es.scheduledCallbacks[i].Timestamp
			}
		}
	}

	// extract callbacks
	var nextTick time.Duration
	for i := len(es.scheduledCallbacks) - 1; i >= 0; i-- {
		if es.scheduledCallbacks[i].Timestamp <= maxTimestamp {
			// if this callback is due, extract it
			callNow = append([]scheduledCallback{es.scheduledCallbacks[i]}, callNow...)
			es.scheduledCallbacks = append(es.scheduledCallbacks[:i], es.scheduledCallbacks[i+1:]...)
		} else {
			// if this callback is not due yet, calculate when
			// should be the next processing
			next := es.scheduledCallbacks[i].AppendTime.Add(es.delay).Sub(now)
			if nextTick == 0 || nextTick > next {
				nextTick = next
			}
		}
	}

	es.mu.Unlock()

	sort.Slice(callNow, func(i, j int) bool {
		return callNow[i].Timestamp < callNow[j].Timestamp
	})
	for _, c := range callNow {
		c.Callback()
	}

	return nextTick
}

func (es *EventSorter) run() {
	for {
		select {
		case <-es.done:
			return
		case t := <-es.ticker.C:
			nextTick := es.process(t)
			if nextTick == 0 {
				// Since the mutex was released, it's possible
				// that a new entry was added in
				// scheduledCallbacks while we were not looking
				es.mu.Lock()
				if len(es.scheduledCallbacks) == 0 {
					es.ticker.Stop()
				}
				es.mu.Unlock()
			} else {
				es.ticker.Reset(nextTick)
			}
		}
	}
}

func (es *EventSorter) Close() {
	if es == nil {
		return
	}
	if es.closed {
		return
	}
	es.closed = true
	close(es.done)
}

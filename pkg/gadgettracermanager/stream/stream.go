// Copyright 2019-2021 The Inspektor Gadget authors
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

package stream

import (
	"sync"
	"time"
)

const (
	HISTORY_SIZE     = 100
	SUB_CHANNEL_SIZE = 250
)

type TimestampedLine struct {
	Line      string
	Timestamp time.Time
	EventLost bool
}

// GadgetStream
type GadgetStream struct {
	mu sync.RWMutex

	previousLines []TimestampedLine

	// subs contains a list of subscribers
	subs map[chan TimestampedLine]struct{}

	closed bool
}

func NewGadgetStream() *GadgetStream {
	return &GadgetStream{
		subs: make(map[chan TimestampedLine]struct{}),
	}
}

func (g *GadgetStream) Subscribe() chan TimestampedLine {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return nil
	}

	ch := make(chan TimestampedLine, SUB_CHANNEL_SIZE)
	for _, l := range g.previousLines {
		ch <- l
	}
	g.subs[ch] = struct{}{}

	return ch
}

func (g *GadgetStream) Unsubscribe(ch chan TimestampedLine) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return
	}

	_, ok := g.subs[ch]
	if ok {
		delete(g.subs, ch)
		close(ch)
	}
}

func (g *GadgetStream) Publish(line string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return
	}

	newLine := TimestampedLine{
		Line:      line,
		Timestamp: time.Now(),
	}

	if len(g.previousLines) == HISTORY_SIZE {
		// Force new array allocation to avoid an ever growing underlying array
		// TODO: check possible performance issue
		g.previousLines = append([]TimestampedLine{}, g.previousLines[1:]...)
	}
	g.previousLines = append(g.previousLines, newLine)

	for ch := range g.subs {
		queuedCount := len(ch)
		switch {
		case queuedCount == cap(ch):
			// Channel full. There is nothing we can do.
			continue
		case queuedCount == cap(ch)-1:
			// Channel almost full. Last chance to signal the problem.
			ch <- TimestampedLine{EventLost: true}
		case queuedCount < cap(ch)-1:
			ch <- newLine
		}
	}
}

func (g *GadgetStream) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for ch := range g.subs {
		close(ch)
	}
	g.closed = true
}

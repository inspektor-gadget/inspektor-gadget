// Copyright 2019-2022 The Inspektor Gadget authors
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

package containercollection

import (
	"sync"
	"time"
)

type EventType int

type FuncNotify func(event PubSubEvent)

const (
	EventTypeAddContainer EventType = iota
	EventTypeRemoveContainer
	EventTypePreCreateContainer
)

func (e *EventType) String() string {
	switch *e {
	case EventTypeRemoveContainer:
		return "DELETED"
	case EventTypePreCreateContainer:
		return "PRECREATE"
	case EventTypeAddContainer:
		fallthrough
	default:
		return "CREATED"
	}
}

func EventTypeFromString(s string) EventType {
	switch s {
	case "DELETED":
		return EventTypeRemoveContainer
	case "PRECREATE":
		return EventTypePreCreateContainer
	case "CREATED":
		fallthrough
	default:
		return EventTypeAddContainer
	}
}

func (e *EventType) MarshalText() (text []byte, err error) {
	return []byte(e.String()), nil
}

func (e *EventType) UnmarshalText(bytes []byte) error {
	*e = EventTypeFromString(string(bytes))
	return nil
}

type PubSubEvent struct {
	Timestamp string     `json:"timestamp,omitempty" column:"timestamp,maxWidth:30" columnTags:"runtime"`
	Type      EventType  `json:"event" column:"event,maxWidth:10" columnTags:"runtime"`
	Container *Container `json:"container"`
}

// GadgetPubSub provides a synchronous publish subscribe mechanism for gadgets
// to be informed of container creation and deletion. It needs to be
// synchronous so that gadgets have time to attach their tracer before the
// container is started.
type GadgetPubSub struct {
	mu sync.RWMutex

	// subs is the set of subscribers
	subs map[interface{}]FuncNotify
}

func NewGadgetPubSub() *GadgetPubSub {
	return &GadgetPubSub{
		subs: make(map[interface{}]FuncNotify),
	}
}

// Subscribe registers the callback to be called for every container event
// published with Publish(). Optionally, the caller can pass an initializer()
// function that is guaranteed to be called before any new container events are
// published.
func (g *GadgetPubSub) Subscribe(key interface{}, callback FuncNotify, initializer func()) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.subs[key] = callback

	if initializer != nil {
		initializer()
	}
}

func (g *GadgetPubSub) Unsubscribe(key interface{}) {
	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.subs, key)
}

func (g *GadgetPubSub) Publish(eventType EventType, container *Container) {
	// Make a copy so we don't keep the lock while actually publishing
	g.mu.RLock()
	copiedSubs := []FuncNotify{}
	for _, callback := range g.subs {
		copiedSubs = append(copiedSubs, callback)
	}
	g.mu.RUnlock()

	var wg sync.WaitGroup
	for _, callback := range copiedSubs {
		wg.Add(1)
		go func(callback FuncNotify) {
			event := PubSubEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      eventType,
				Container: container,
			}
			callback(event)
			wg.Done()
		}(callback)
	}

	wg.Wait()
}

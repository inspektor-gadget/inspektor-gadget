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
	"testing"
)

func TestPubSub(t *testing.T) {
	p := NewGadgetPubSub()
	if p == nil {
		t.Fatalf("Failed to create new pubsub")
	}

	var event PubSubEvent
	done := make(chan struct{}, 1)
	counter := 0
	key := "callback1"
	callback := func(e PubSubEvent) {
		event = e
		counter++
		done <- struct{}{}
	}

	p.Subscribe(key, callback, nil)

	p.Publish(
		EventTypeRemoveContainer,
		&Container{
			Runtime: RuntimeMetadata{
				ContainerID: "container1",
			},
		},
	)
	_, ok := <-done
	if !ok {
		t.Fatalf("Failed to receive event from callback")
	}

	if event.Type != EventTypeRemoveContainer {
		t.Fatalf("Failed to receive correct event of type EVENT_TYPE_REMOVE_CONTAINER")
	}
	if event.Container.Runtime.ContainerID != "container1" {
		t.Fatalf("Failed to receive correct event")
	}

	p.Unsubscribe(key)
	p.Publish(
		EventTypeRemoveContainer,
		&Container{
			Runtime: RuntimeMetadata{
				ContainerID: "container2",
			},
		},
	)
	if counter != 1 {
		t.Fatalf("Callback called too many times")
	}
}

func TestPubSubVerifyPointerToContainer(t *testing.T) {
	p := NewGadgetPubSub()
	if p == nil {
		t.Fatalf("Failed to create new pubsub")
	}

	c := &Container{
		Runtime: RuntimeMetadata{
			ContainerID: "container1",
		},
	}

	var receivedC *Container

	key := "callback1"
	done := make(chan struct{}, 1)
	callback := func(e PubSubEvent) {
		receivedC = e.Container
		done <- struct{}{}
	}

	p.Subscribe(key, callback, nil)
	p.Publish(EventTypeAddContainer, c)

	_, ok := <-done
	if !ok {
		t.Fatalf("Failed to receive event from callback")
	}

	p.Unsubscribe(key)

	if receivedC != c {
		t.Fatalf("Pointer doesn't correspond to original object")
	}
}

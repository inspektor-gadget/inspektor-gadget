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

package pubsub

import (
	"testing"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
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

	p.Publish(EventTypeRemoveContainer, pb.ContainerDefinition{Id: "container1"})
	_, ok := <-done
	if !ok {
		t.Fatalf("Failed to receive event from callback")
	}

	if event.Type != EventTypeRemoveContainer {
		t.Fatalf("Failed to receive correct event of type EVENT_TYPE_REMOVE_CONTAINER")
	}
	if event.Container.Id != "container1" {
		t.Fatalf("Failed to receive correct event")
	}

	p.Unsubscribe(key)
	p.Publish(EventTypeRemoveContainer, pb.ContainerDefinition{Id: "container2"})
	if counter != 1 {
		t.Fatalf("Callback called too many times")
	}
}

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

package gadgettracermanager

import (
	"fmt"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

func TestTracer(t *testing.T) {
	g, err := NewServer(&Conf{NodeName: "fake-node", HookMode: "none", TestOnly: true})
	if err != nil {
		t.Fatalf("Failed to create new server: %v", err)
	}

	// Add 3 Tracers
	for i := 0; i < 3; i++ {
		err := g.AddTracer(
			fmt.Sprintf("my_tracer_id%d", i),
			containercollection.ContainerSelector{
				Namespace: fmt.Sprintf("this-namespace%d", i),
			},
		)
		if err != nil {
			t.Fatalf("Failed to add tracer: %v", err)
		}
	}

	if g.tracerCollection.TracerCount() != 3 {
		t.Fatalf("Error while checking tracers: len %d", g.tracerCollection.TracerCount())
	}

	// Check error on duplicate tracer
	err = g.AddTracer(
		fmt.Sprintf("my_tracer_id%d", 0),
		containercollection.ContainerSelector{
			Namespace: fmt.Sprintf("this-namespace%d", 0),
		},
	)
	if err == nil {
		t.Fatal("Error while trying to add a duplicate tracer: duplicate not detected")
	}

	// Remove 1 Tracer
	err = g.RemoveTracer(fmt.Sprintf("my_tracer_id%d", 1))
	if err != nil {
		t.Fatalf("Failed to remove tracer: %v", err)
	}

	// Remove non-existent Tracer
	err = g.RemoveTracer(fmt.Sprintf("my_tracer_id%d", 99))
	if err == nil {
		t.Fatal("Error while removing non-existent tracer: no error detected")
	}

	// Check content
	if g.tracerCollection.TracerCount() != 2 {
		t.Fatalf("Error while checking tracers: len %d", g.tracerCollection.TracerCount())
	}
	if !g.tracerCollection.TracerExists("my_tracer_id0") {
		t.Fatalf("Error while checking tracer %s: not found", "my_tracer_id0")
	}
	if !g.tracerCollection.TracerExists("my_tracer_id2") {
		t.Fatalf("Error while checking tracer %s: not found", "my_tracer_id2")
	}
}

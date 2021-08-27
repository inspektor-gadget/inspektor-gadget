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
	"context"
	"fmt"
	"reflect"
	"testing"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

func TestSelector(t *testing.T) {
	table := []struct {
		description string
		match       bool
		selector    *pb.ContainerSelector
		container   *pb.ContainerDefinition
	}{
		{
			description: "Selector without filter",
			match:       true,
			selector:    &pb.ContainerSelector{},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
			},
		},
		{
			description: "Selector with all filters",
			match:       true,
			selector: &pb.ContainerSelector{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					&pb.Label{Key: "key1", Value: "value1"},
					&pb.Label{Key: "key2", Value: "value2"},
				},
			},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					&pb.Label{Key: "unrelated-label", Value: "here"},
					&pb.Label{Key: "key1", Value: "value1"},
					&pb.Label{Key: "key2", Value: "value2"},
				},
			},
		},
		{
			description: "Podname does not match",
			match:       false,
			selector: &pb.ContainerSelector{
				Namespace: "this-namespace",
				Podname:   "this-pod",
			},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "a-misnamed-pod",
				Name:      "this-container",
			},
		},
		{
			description: "One label doesn't match",
			match:       false,
			selector: &pb.ContainerSelector{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					&pb.Label{Key: "key1", Value: "value1"},
					&pb.Label{Key: "key2", Value: "value2"},
				},
			},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					&pb.Label{Key: "key1", Value: "value1"},
					&pb.Label{Key: "key2", Value: "something-else"},
				},
			},
		},
	}

	for i, entry := range table {
		result := containerSelectorMatches(entry.selector, entry.container)
		if entry.match != result {
			t.Fatalf("Failed test %q (index %d): result %v expected %v",
				entry.description, i, result, entry.match)
		}
	}
}

func TestTracer(t *testing.T) {
	g, err := newServer("fake-node", false, false, false)
	if err != nil {
		t.Fatalf("Failed to create new server: %v", err)
	}

	ctx := context.TODO()

	// Add 3 Tracers
	for i := 0; i < 3; i++ {
		respAddTracer, err := g.AddTracer(ctx, &pb.AddTracerRequest{
			Id: fmt.Sprintf("my_tracer_id%d", i),
			Selector: &pb.ContainerSelector{
				Namespace: fmt.Sprintf("this-namespace%d", i),
			},
		})
		if err != nil {
			t.Fatalf("Failed to add tracer: %v", err)
		}
		if respAddTracer.Id != fmt.Sprintf("my_tracer_id%d", i) {
			t.Fatalf("Error while adding tracer: got id %q", respAddTracer.Id)
		}
	}

	if len(g.tracers) != 3 {
		t.Fatalf("Error while checking tracers: len %d", len(g.tracers))
	}

	// Check error on duplicate tracer
	_, err = g.AddTracer(ctx, &pb.AddTracerRequest{
		Id: fmt.Sprintf("my_tracer_id%d", 0),
		Selector: &pb.ContainerSelector{
			Namespace: fmt.Sprintf("this-namespace%d", 0),
		},
	})
	if err == nil {
		t.Fatal("Error while trying to add a duplicate tracer: duplicate not detected")
	}

	// Remove 1 Tracer
	respRemoveTracer, err := g.RemoveTracer(ctx, &pb.TracerID{
		Id: fmt.Sprintf("my_tracer_id%d", 1),
	})
	if err != nil {
		t.Fatalf("Failed to remove tracer: %v", err)
	}
	if respRemoveTracer == nil {
		t.Fatal("Error while removing tracer: invalid response")
	}

	// Remove non-existent Tracer
	respRemoveTracer, err = g.RemoveTracer(ctx, &pb.TracerID{
		Id: fmt.Sprintf("my_tracer_id%d", 99),
	})
	if err == nil {
		t.Fatal("Error while removing non-existent tracer: no error detected")
	}
	if respRemoveTracer != nil {
		t.Fatal("Error while removing tracer: invalid response")
	}

	// Check content
	if len(g.tracers) != 2 {
		t.Fatalf("Error while checking tracers: len %d", len(g.tracers))
	}
	_, ok := g.tracers["my_tracer_id0"]
	if !ok {
		t.Fatalf("Error while checking tracer %s: not found", "my_tracer_id0")
	}
	_, ok = g.tracers["my_tracer_id2"]
	if !ok {
		t.Fatalf("Error while checking tracer %s: not found", "my_tracer_id2")
	}
}

func TestContainer(t *testing.T) {
	g, err := newServer("fake-node", false, false, false)
	if err != nil {
		t.Fatalf("Failed to create new server: %v", err)
	}

	ctx := context.TODO()

	// Add 3 Containers
	for i := 0; i < 3; i++ {
		respAddContainer, err := g.AddContainer(ctx, &pb.ContainerDefinition{
			Id:        fmt.Sprintf("abcde%d", i),
			Namespace: "this-namespace",
			Podname:   "my-pod",
			Name:      fmt.Sprintf("container%d", i),
			Mntns:     55555 + uint64(i),
			Pid:       uint32(100 + i),
		})
		if err != nil {
			t.Fatalf("Failed to add container: %v", err)
		}
		if respAddContainer == nil {
			t.Fatal("Error while adding container: invalid response")
		}
	}

	// Check error on duplicate container
	_, err = g.AddContainer(ctx, &pb.ContainerDefinition{
		Id:        fmt.Sprintf("abcde%d", 0),
		Namespace: "this-namespace",
		Podname:   "my-pod",
		Name:      fmt.Sprintf("container%d", 0),
		Mntns:     55555 + uint64(0),
		Pid:       uint32(100),
	})
	if err == nil {
		t.Fatal("Error while adding duplicate container: duplicate not detected")
	}

	// Remove 1 Container
	respRemoveContainer, err := g.RemoveContainer(ctx, &pb.ContainerDefinition{
		Id: "abcde1",
	})
	if err != nil {
		t.Fatalf("Failed to remove container: %v", err)
	}
	if respRemoveContainer == nil {
		t.Fatal("Error while removing container: invalid response")
	}

	// Remove non-existent Container
	_, err = g.RemoveContainer(ctx, &pb.ContainerDefinition{
		Id: "abcde99",
	})
	if err == nil {
		t.Fatal("Error while removing non-existent container: no error detected")
	}

	// Check content
	if len(g.containers) != 2 {
		t.Fatalf("Error while checking containers: len %d", len(g.containers))
	}
	_, ok := g.containers["abcde0"]
	if !ok {
		t.Fatalf("Error while checking container %s: not found", "abcde0")
	}
	_, ok = g.containers["abcde2"]
	if !ok {
		t.Fatalf("Error while checking container %s: not found", "abcde2")
	}

	// Check content using LookupMntnsByPod
	mntnsByContainer := g.LookupMntnsByPod("this-namespace", "my-pod")
	if !reflect.DeepEqual(mntnsByContainer, map[string]uint64{"container0": 55555, "container2": 55557}) {
		t.Fatalf("Error while looking up mount ns by Pod: unexpected %v", mntnsByContainer)
	}
	mntnsByContainer = g.LookupMntnsByPod("this-namespace", "this-other-pod")
	if !reflect.DeepEqual(mntnsByContainer, map[string]uint64{}) {
		t.Fatalf("Error while looking up mount ns by Pod: unexpected %v", mntnsByContainer)
	}

	// Check content using LookupMntnsByContainer
	mntns := g.LookupMntnsByContainer("this-namespace", "my-pod", "container0")
	if mntns != 55555 {
		t.Fatalf("Error while looking up container0: unexpected mntns %v", mntns)
	}
	mntns = g.LookupMntnsByContainer("this-namespace", "my-pod", "container1")
	if mntns != 0 {
		t.Fatalf("Error while looking up container1: unexpected mntns %v", mntns)
	}
	mntns = g.LookupMntnsByContainer("this-namespace", "my-pod", "container2")
	if mntns != 55557 {
		t.Fatalf("Error while looking up container2: unexpected mntns %v", mntns)
	}

	// Check content using LookupPIDByPod
	pidByContainer := g.LookupPIDByPod("this-namespace", "my-pod")
	if !reflect.DeepEqual(pidByContainer, map[string]uint32{"container0": 100, "container2": 102}) {
		t.Fatalf("Error while looking up PID by Pod: unexpected %v", pidByContainer)
	}
	pidByContainer = g.LookupPIDByPod("this-namespace", "this-other-pod")
	if !reflect.DeepEqual(pidByContainer, map[string]uint32{}) {
		t.Fatalf("Error while looking up PID by Pod: unexpected %v", pidByContainer)
	}

	// Check content using LookupPIDByContainer
	pid := g.LookupPIDByContainer("this-namespace", "my-pod", "container0")
	if pid != 100 {
		t.Fatalf("Error while looking up container0: unexpected pid %v", pid)
	}
	pid = g.LookupPIDByContainer("this-namespace", "my-pod", "container1")
	if pid != 0 {
		t.Fatalf("Error while looking up container1: unexpected pid %v", pid)
	}
	pid = g.LookupPIDByContainer("this-namespace", "my-pod", "container2")
	if pid != 102 {
		t.Fatalf("Error while looking up container2: unexpected pid %v", pid)
	}
}

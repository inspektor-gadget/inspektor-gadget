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

func TestTracer(t *testing.T) {
	g, err := newServer(&Conf{NodeName: "fake-node", HookMode: "none", TestOnly: true})
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
	g, err := newServer(&Conf{NodeName: "fake-node", HookMode: "none", TestOnly: true})
	if err != nil {
		t.Fatalf("Failed to create new server: %v", err)
	}

	ctx := context.TODO()

	// Add 3 Containers
	for i := 0; i < 3; i++ {
		respAddContainer, err := g.AddContainer(ctx, &pb.ContainerDefinition{
			Id:         fmt.Sprintf("abcde%d", i),
			Namespace:  "this-namespace",
			Podname:    "my-pod",
			Name:       fmt.Sprintf("container%d", i),
			Mntns:      55555 + uint64(i),
			Pid:        uint32(100 + i),
			CgroupPath: "/none",
			CgroupId:   1,
			OwnerReference: &pb.OwnerReference{
				Uid: fmt.Sprintf("abcde%d", i),
			},
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
	if g.ContainerLen() != 2 {
		t.Fatalf("Error while checking containers: len %d", g.ContainerLen())
	}
	if g.GetContainer("abcde0") == nil {
		t.Fatalf("Error while checking container %s: not found", "abcde0")
	}
	if g.GetContainer("abcde2") == nil {
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

	// Check content using LookupOwnerReferenceByMntns
	ownerRef := g.LookupOwnerReferenceByMntns(55555)
	if ownerRef == nil || ownerRef.Uid != "abcde0" {
		t.Fatalf("Error while looking up owner reference: unexpected %v", ownerRef)
	}

	ownerRef = g.LookupOwnerReferenceByMntns(55557)
	if ownerRef == nil || ownerRef.Uid != "abcde2" {
		t.Fatalf("Error while looking up owner reference: unexpected %v", ownerRef)
	}

	// Non-existent mntns
	ownerRef = g.LookupOwnerReferenceByMntns(55556)
	if ownerRef != nil {
		t.Fatalf("Error while looking up owner reference: unexpected %v", ownerRef)
	}

	// Check LookupContainerByMntns
	containerByMntns0 := g.LookupContainerByMntns(55555)
	if containerByMntns0.Name != "container0" {
		t.Fatalf("Error in LookupContainerByMntns: expected %s, found %s", "container0",
			containerByMntns0.Name)
	}

	// Check LookupContainerByMntns
	containerByMntns2 := g.LookupContainerByMntns(55555 + 2)
	if containerByMntns2.Name != "container2" {
		t.Fatalf("Error in LookupContainerByMntns: expected %s, found %s", "container2",
			containerByMntns2.Name)
	}

	containerByMntnsNotFound := g.LookupContainerByMntns(989898)
	if containerByMntnsNotFound != nil {
		t.Fatalf("Error in LookupContainerByMntns: returned non nil")
	}

	// Add new container with same pod and container name of container0 but in different namespace
	respAddContainer, err := g.AddContainer(ctx, &pb.ContainerDefinition{
		Id:        "abcde0-different",
		Namespace: "another-namespace",
		Podname:   "my-pod",
		Name:      "container0",
		Labels: []*pb.Label{
			{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"},
		},
		CgroupPath: "/none",
		CgroupId:   1,
		Mntns:      1,
	})
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}
	if respAddContainer == nil {
		t.Fatal("Error while adding container: invalid response")
	}

	// Look up containers with label 'key1=value1'
	selectedContainers := g.GetContainersBySelector(&pb.ContainerSelector{
		Labels: []*pb.Label{
			{Key: "key1", Value: "value1"},
		},
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up containers by one label: invalid number of matches")
	}
	found := false
	for _, l := range selectedContainers[0].Labels {
		if l.Key == "key1" && l.Value == "value1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Error while looking up containers by one label: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up containers with label 'key1=value1' and 'key2=value2'
	selector := pb.ContainerSelector{
		Labels: []*pb.Label{
			{Key: "key1", Value: "value1"},
			{Key: "key2", Value: "value2"},
		},
	}
	selectedContainers = g.GetContainersBySelector(&selector)
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up containers by multiple labels: invalid number of matches")
	}
	for _, sl := range selector.Labels {
		found := false
		for _, l := range selectedContainers[0].Labels {
			if l.Key == sl.Key && l.Value == sl.Value {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Error while looking up containers by multiple labels: unexpected container %+v",
				selectedContainers[0])
		}
	}

	// Look up containers in 'this-namespace'
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by namespace: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.Namespace != "this-namespace" {
			t.Fatalf("Error while looking up containers by namespace: unexpected container %+v",
				container)
		}
	}

	// Look up containers in 'this-namespace' and 'my-pod'
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
		Podname:   "my-pod",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by namespace and pod: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.Namespace != "this-namespace" || container.Podname != "my-pod" {
			t.Fatalf("Error while looking up containers by namespace and pod: unexpected container %+v",
				container)
		}
	}

	// Look up containers named 'container0' anywhere
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Name: "container0",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by name: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.Name != "container0" {
			t.Fatalf("Error while looking up containers by name: unexpected container %+v",
				container)
		}
	}

	// Look up containers named 'container0' in 'my-pod' but any namespace
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Podname: "my-pod",
		Name:    "container0",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by name and pod: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.Podname != "my-pod" || container.Name != "container0" {
			t.Fatalf("Error while looking up containers by name and pod: unexpected container %+v",
				container)
		}
	}

	// Look up container0 in 'this-namespace' and 'my-pod'
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
		Podname:   "my-pod",
		Name:      "container0",
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].Namespace != "this-namespace" || selectedContainers[0].Podname != "my-pod" || selectedContainers[0].Name != "container0" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up container0 in 'another-namespace' and 'my-pod'
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "another-namespace",
		Podname:   "my-pod",
		Name:      "container0",
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].Namespace != "another-namespace" || selectedContainers[0].Podname != "my-pod" || selectedContainers[0].Name != "container0" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up container2 in 'this-namespace' and 'my-pod'
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
		Podname:   "my-pod",
		Name:      "container2",
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].Namespace != "this-namespace" || selectedContainers[0].Podname != "my-pod" || selectedContainers[0].Name != "container2" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up a non-existent container
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
		Podname:   "my-pod",
		Name:      "non-existent",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up a non-existent container")
	}

	// Look up containers in a non-existent pod
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
		Podname:   "non-existent",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent pod")
	}

	// Look up containers in a non-existent pod
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "this-namespace",
		Podname:   "non-existent",
		Name:      "container0",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}

	// Look up containers in a non-existent namespace
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "non-existent",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}

	// Look up containers in a non-existent namespace
	selectedContainers = g.GetContainersBySelector(&pb.ContainerSelector{
		Namespace: "non-existent",
		Podname:   "my-pod",
		Name:      "container0",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}
}

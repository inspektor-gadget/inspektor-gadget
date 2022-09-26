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

package containercollection

import (
	"fmt"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestSelector(t *testing.T) {
	table := []struct {
		description string
		match       bool
		selector    *ContainerSelector
		container   *Container
	}{
		{
			description: "Selector without filter",
			match:       true,
			selector:    &ContainerSelector{},
			container: &Container{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
			},
		},
		{
			description: "Selector with all filters",
			match:       true,
			selector: &ContainerSelector{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
				KubernetesLabels: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
			container: &Container{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
				KubernetesLabels: map[string]string{
					"unrelated-label": "here",
					"key1":            "value1",
					"key2":            "value2",
				},
			},
		},
		{
			description: "Podname does not match",
			match:       false,
			selector: &ContainerSelector{
				KubernetesNamespace: "this-namespace",
				KubernetesPodName:   "this-pod",
			},
			container: &Container{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "a-misnamed-pod",
				KubernetesContainerName: "this-container",
			},
		},
		{
			description: "One label doesn't match",
			match:       false,
			selector: &ContainerSelector{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
				KubernetesLabels: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
			container: &Container{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
				KubernetesLabels: map[string]string{
					"key1": "value1",
					"key2": "something-else",
				},
			},
		},
		{
			description: "Several namespaces without match",
			match:       false,
			selector: &ContainerSelector{
				KubernetesNamespace: "ns1,ns2,ns3",
				KubernetesPodName:   "this-pod",
			},
			container: &Container{
				KubernetesNamespace:     "this-namespace",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
			},
		},
		{
			description: "Several namespaces with match",
			match:       true,
			selector: &ContainerSelector{
				KubernetesNamespace: "ns1,ns2,ns3",
				KubernetesPodName:   "this-pod",
			},
			container: &Container{
				KubernetesNamespace:     "ns2",
				KubernetesPodName:       "this-pod",
				KubernetesContainerName: "this-container",
			},
		},
	}

	for i, entry := range table {
		result := ContainerSelectorMatches(entry.selector, entry.container)
		if entry.match != result {
			t.Fatalf("Failed test %q (index %d): result %v expected %v",
				entry.description, i, result, entry.match)
		}
	}
}

func TestContainerResolver(t *testing.T) {
	opts := []ContainerCollectionOption{}

	cc := &ContainerCollection{}
	err := cc.Initialize(opts...)
	if err != nil {
		t.Fatalf("Failed to initialize container collection: %s", err)
	}

	// Add 3 Containers
	for i := 0; i < 3; i++ {
		cc.AddContainer(&Container{
			ID:                      fmt.Sprintf("abcde%d", i),
			KubernetesNamespace:     "this-namespace",
			KubernetesPodName:       "my-pod",
			KubernetesContainerName: fmt.Sprintf("container%d", i),
			Mntns:                   55555 + uint64(i),
			Pid:                     uint32(100 + i),
			CgroupPath:              "/none",
			CgroupID:                1,
			ownerReference: &metav1.OwnerReference{
				UID: types.UID(fmt.Sprintf("abcde%d", i)),
			},
		})
	}

	// Remove 1 Container
	cc.RemoveContainer("abcde1")

	// Remove non-existent Container
	cc.RemoveContainer("abcde99")

	// Check content
	if cc.ContainerLen() != 2 {
		t.Fatalf("Error while checking containers: len %d", cc.ContainerLen())
	}
	if cc.GetContainer("abcde0") == nil {
		t.Fatalf("Error while checking container %s: not found", "abcde0")
	}
	if cc.GetContainer("abcde2") == nil {
		t.Fatalf("Error while checking container %s: not found", "abcde2")
	}

	// Check content using LookupMntnsByPod
	mntnsByContainer := cc.LookupMntnsByPod("this-namespace", "my-pod")
	if !reflect.DeepEqual(mntnsByContainer, map[string]uint64{"container0": 55555, "container2": 55557}) {
		t.Fatalf("Error while looking up mount ns by Pod: unexpected %v", mntnsByContainer)
	}
	mntnsByContainer = cc.LookupMntnsByPod("this-namespace", "this-other-pod")
	if !reflect.DeepEqual(mntnsByContainer, map[string]uint64{}) {
		t.Fatalf("Error while looking up mount ns by Pod: unexpected %v", mntnsByContainer)
	}

	// Check content using LookupMntnsByContainer
	mntns := cc.LookupMntnsByContainer("this-namespace", "my-pod", "container0")
	if mntns != 55555 {
		t.Fatalf("Error while looking up container0: unexpected mntns %v", mntns)
	}
	mntns = cc.LookupMntnsByContainer("this-namespace", "my-pod", "container1")
	if mntns != 0 {
		t.Fatalf("Error while looking up container1: unexpected mntns %v", mntns)
	}
	mntns = cc.LookupMntnsByContainer("this-namespace", "my-pod", "container2")
	if mntns != 55557 {
		t.Fatalf("Error while looking up container2: unexpected mntns %v", mntns)
	}

	// Check content using LookupPIDByPod
	pidByContainer := cc.LookupPIDByPod("this-namespace", "my-pod")
	if !reflect.DeepEqual(pidByContainer, map[string]uint32{"container0": 100, "container2": 102}) {
		t.Fatalf("Error while looking up PID by Pod: unexpected %v", pidByContainer)
	}
	pidByContainer = cc.LookupPIDByPod("this-namespace", "this-other-pod")
	if !reflect.DeepEqual(pidByContainer, map[string]uint32{}) {
		t.Fatalf("Error while looking up PID by Pod: unexpected %v", pidByContainer)
	}

	// Check content using LookupPIDByContainer
	pid := cc.LookupPIDByContainer("this-namespace", "my-pod", "container0")
	if pid != 100 {
		t.Fatalf("Error while looking up container0: unexpected pid %v", pid)
	}
	pid = cc.LookupPIDByContainer("this-namespace", "my-pod", "container1")
	if pid != 0 {
		t.Fatalf("Error while looking up container1: unexpected pid %v", pid)
	}
	pid = cc.LookupPIDByContainer("this-namespace", "my-pod", "container2")
	if pid != 102 {
		t.Fatalf("Error while looking up container2: unexpected pid %v", pid)
	}

	// Check content using LookupOwnerReferenceByMntns
	ownerRef := cc.LookupOwnerReferenceByMntns(55555)
	if ownerRef == nil || ownerRef.UID != "abcde0" {
		t.Fatalf("Error while looking up owner reference: unexpected %v", ownerRef)
	}

	ownerRef = cc.LookupOwnerReferenceByMntns(55557)
	if ownerRef == nil || ownerRef.UID != "abcde2" {
		t.Fatalf("Error while looking up owner reference: unexpected %v", ownerRef)
	}

	// Non-existent mntns
	ownerRef = cc.LookupOwnerReferenceByMntns(55556)
	if ownerRef != nil {
		t.Fatalf("Error while looking up owner reference: unexpected %v", ownerRef)
	}

	// Check LookupContainerByMntns
	containerByMntns0 := cc.LookupContainerByMntns(55555)
	if containerByMntns0.KubernetesContainerName != "container0" {
		t.Fatalf("Error in LookupContainerByMntns: expected %s, found %s", "container0",
			containerByMntns0.KubernetesContainerName)
	}

	// Check LookupContainerByMntns
	containerByMntns2 := cc.LookupContainerByMntns(55555 + 2)
	if containerByMntns2.KubernetesContainerName != "container2" {
		t.Fatalf("Error in LookupContainerByMntns: expected %s, found %s", "container2",
			containerByMntns2.KubernetesContainerName)
	}

	containerByMntnsNotFound := cc.LookupContainerByMntns(989898)
	if containerByMntnsNotFound != nil {
		t.Fatalf("Error in LookupContainerByMntns: returned non nil")
	}

	// Add new container with same pod and container name of container0 but in different namespace
	cc.AddContainer(&Container{
		ID:                      "abcde0-different",
		KubernetesNamespace:     "another-namespace",
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "container0",
		KubernetesLabels: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	})

	// Look up containers with label 'key1=value1'
	selectedContainers := cc.GetContainersBySelector(&ContainerSelector{
		KubernetesLabels: map[string]string{
			"key1": "value1",
		},
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up containers by one label: invalid number of matches")
	}
	if v, found := selectedContainers[0].KubernetesLabels["key1"]; !found || v != "value1" {
		t.Fatalf("Error while looking up containers by one label: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up containers with label 'key1=value1' and 'key2=value2'
	selector := ContainerSelector{
		KubernetesLabels: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}
	selectedContainers = cc.GetContainersBySelector(&selector)
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up containers by multiple labels: invalid number of matches")
	}
	for sk, sv := range selector.KubernetesLabels {
		if v, found := selectedContainers[0].KubernetesLabels[sk]; !found || v != sv {
			t.Fatalf("Error while looking up containers by multiple labels: unexpected container %+v",
				selectedContainers[0])
		}
	}

	// Look up containers in 'this-namespace'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace: "this-namespace",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by namespace: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.KubernetesNamespace != "this-namespace" {
			t.Fatalf("Error while looking up containers by namespace: unexpected container %+v",
				container)
		}
	}

	// Look up containers in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace: "this-namespace",
		KubernetesPodName:   "my-pod",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by namespace and pod: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.KubernetesNamespace != "this-namespace" || container.KubernetesPodName != "my-pod" {
			t.Fatalf("Error while looking up containers by namespace and pod: unexpected container %+v",
				container)
		}
	}

	// Look up containers named 'container0' anywhere
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesContainerName: "container0",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by name: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.KubernetesContainerName != "container0" {
			t.Fatalf("Error while looking up containers by name: unexpected container %+v",
				container)
		}
	}

	// Look up containers named 'container0' in 'my-pod' but any namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "container0",
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by name and pod: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.KubernetesPodName != "my-pod" || container.KubernetesContainerName != "container0" {
			t.Fatalf("Error while looking up containers by name and pod: unexpected container %+v",
				container)
		}
	}

	// Look up container0 in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace:     "this-namespace",
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "container0",
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].KubernetesNamespace != "this-namespace" || selectedContainers[0].KubernetesPodName != "my-pod" || selectedContainers[0].KubernetesContainerName != "container0" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up container0 in 'another-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace:     "another-namespace",
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "container0",
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].KubernetesNamespace != "another-namespace" || selectedContainers[0].KubernetesPodName != "my-pod" || selectedContainers[0].KubernetesContainerName != "container0" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up container2 in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace:     "this-namespace",
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "container2",
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].KubernetesNamespace != "this-namespace" || selectedContainers[0].KubernetesPodName != "my-pod" || selectedContainers[0].KubernetesContainerName != "container2" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up a non-existent container
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace:     "this-namespace",
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "non-existent",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up a non-existent container")
	}

	// Look up containers in a non-existent pod
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace: "this-namespace",
		KubernetesPodName:   "non-existent",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent pod")
	}

	// Look up containers in a non-existent pod
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace:     "this-namespace",
		KubernetesPodName:       "non-existent",
		KubernetesContainerName: "container0",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}

	// Look up containers in a non-existent namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace: "non-existent",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}

	// Look up containers in a non-existent namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		KubernetesNamespace:     "non-existent",
		KubernetesPodName:       "my-pod",
		KubernetesContainerName: "container0",
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}
}

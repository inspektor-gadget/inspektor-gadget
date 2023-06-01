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
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
						Container: "this-container",
					},
				},
			},
		},
		{
			description: "Selector with all filters",
			match:       true,
			selector: &ContainerSelector{
				K8sSelector: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
						Container: "this-container",
					},
					Labels: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
						Container: "this-container",
					},
					Labels: map[string]string{
						"unrelated-label": "here",
						"key1":            "value1",
						"key2":            "value2",
					},
				},
			},
		},
		{
			description: "Podname does not match",
			match:       false,
			selector: &ContainerSelector{
				K8sSelector: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "a-misnamed-pod",
						Container: "this-container",
					},
				},
			},
		},
		{
			description: "One label doesn't match",
			match:       false,
			selector: &ContainerSelector{
				K8sSelector: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
						Container: "this-container",
					},
					Labels: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
						Container: "this-container",
					},
					Labels: map[string]string{
						"key1": "value1",
						"key2": "something-else",
					},
				},
			},
		},
		{
			description: "Several namespaces without match",
			match:       false,
			selector: &ContainerSelector{
				K8sSelector: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "ns1,ns2,ns3",
						Pod:       "this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						Pod:       "this-pod",
						Container: "this-container",
					},
				},
			},
		},
		{
			description: "Several namespaces with match",
			match:       true,
			selector: &ContainerSelector{
				K8sSelector: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "ns1,ns2,ns3",
						Pod:       "this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "ns2",
						Pod:       "this-pod",
						Container: "this-container",
					},
				},
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
			Runtime: RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: fmt.Sprintf("abcde%d", i),
				},
			},
			Mntns:      55555 + uint64(i),
			Pid:        uint32(100 + i),
			CgroupPath: "/none",
			CgroupID:   1,
			K8s: K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace: "this-namespace",
					Pod:       "my-pod",
					Container: fmt.Sprintf("container%d", i),
				},
				ownerReference: &metav1.OwnerReference{
					UID: k8sTypes.UID(fmt.Sprintf("abcde%d", i)),
				},
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
	if containerByMntns0.K8s.Container != "container0" {
		t.Fatalf("Error in LookupContainerByMntns: expected %s, found %s", "container0",
			containerByMntns0.K8s.Container)
	}

	// Check LookupContainerByMntns
	containerByMntns2 := cc.LookupContainerByMntns(55555 + 2)
	if containerByMntns2.K8s.Container != "container2" {
		t.Fatalf("Error in LookupContainerByMntns: expected %s, found %s", "container2",
			containerByMntns2.K8s.Container)
	}

	containerByMntnsNotFound := cc.LookupContainerByMntns(989898)
	if containerByMntnsNotFound != nil {
		t.Fatalf("Error in LookupContainerByMntns: returned non nil")
	}

	// Add new container with same pod and container name of container0 but in different namespace
	cc.AddContainer(&Container{
		Runtime: RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "abcde0-different",
			},
		},
		K8s: K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "another-namespace",
				Pod:       "my-pod",
				Container: "container0",
			},
			Labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	})

	// Look up containers with label 'key1=value1'
	selectedContainers := cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			Labels: map[string]string{
				"key1": "value1",
			},
		},
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up containers by one label: invalid number of matches")
	}
	if v, found := selectedContainers[0].K8s.Labels["key1"]; !found || v != "value1" {
		t.Fatalf("Error while looking up containers by one label: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up containers with label 'key1=value1' and 'key2=value2'
	selector := ContainerSelector{
		K8sSelector: K8sSelector{
			Labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}
	selectedContainers = cc.GetContainersBySelector(&selector)
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up containers by multiple labels: invalid number of matches")
	}
	for sk, sv := range selector.K8sSelector.Labels {
		if v, found := selectedContainers[0].K8s.Labels[sk]; !found || v != sv {
			t.Fatalf("Error while looking up containers by multiple labels: unexpected container %+v",
				selectedContainers[0])
		}
	}

	// Look up containers in 'this-namespace'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
			},
		},
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by namespace: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.K8s.Namespace != "this-namespace" {
			t.Fatalf("Error while looking up containers by namespace: unexpected container %+v",
				container)
		}
	}

	// Look up containers in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				Pod:       "my-pod",
			},
		},
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by namespace and pod: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.K8s.Namespace != "this-namespace" || container.K8s.Pod != "my-pod" {
			t.Fatalf("Error while looking up containers by namespace and pod: unexpected container %+v",
				container)
		}
	}

	// Look up containers named 'container0' anywhere
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Container: "container0",
			},
		},
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by name: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.K8s.Container != "container0" {
			t.Fatalf("Error while looking up containers by name: unexpected container %+v",
				container)
		}
	}

	// Look up containers named 'container0' in 'my-pod' but any namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Pod:       "my-pod",
				Container: "container0",
			},
		},
	})
	if len(selectedContainers) != 2 {
		t.Fatalf("Error while looking up containers by name and pod: invalid number of matches")
	}
	for _, container := range selectedContainers {
		if container.K8s.Pod != "my-pod" || container.K8s.Container != "container0" {
			t.Fatalf("Error while looking up containers by name and pod: unexpected container %+v",
				container)
		}
	}

	// Look up container0 in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				Pod:       "my-pod",
				Container: "container0",
			},
		},
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].K8s.Namespace != "this-namespace" || selectedContainers[0].K8s.Pod != "my-pod" || selectedContainers[0].K8s.Container != "container0" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up container0 in 'another-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "another-namespace",
				Pod:       "my-pod",
				Container: "container0",
			},
		},
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].K8s.Namespace != "another-namespace" || selectedContainers[0].K8s.Pod != "my-pod" || selectedContainers[0].K8s.Container != "container0" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up container2 in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				Pod:       "my-pod",
				Container: "container2",
			},
		},
	})
	if len(selectedContainers) != 1 {
		t.Fatalf("Error while looking up specific container: invalid number of matches")
	}
	if selectedContainers[0].K8s.Namespace != "this-namespace" || selectedContainers[0].K8s.Pod != "my-pod" || selectedContainers[0].K8s.Container != "container2" {
		t.Fatalf("Error while looking up specific container: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up a non-existent container
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				Pod:       "my-pod",
				Container: "non-existent",
			},
		},
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up a non-existent container")
	}

	// Look up containers in a non-existent pod
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				Pod:       "non-existent",
			},
		},
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent pod")
	}

	// Look up containers in a non-existent pod
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				Pod:       "non-existent",
				Container: "container0",
			},
		},
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}

	// Look up containers in a non-existent namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "non-existent",
			},
		},
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}

	// Look up containers in a non-existent namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8sSelector: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "non-existent",
				Pod:       "my-pod",
				Container: "container0",
			},
		},
	})
	if len(selectedContainers) != 0 {
		t.Fatalf("Error while looking up containers in a non-existent namespace")
	}
}

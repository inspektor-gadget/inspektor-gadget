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
	"testing"

	"github.com/stretchr/testify/require"
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
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Selector with all filters",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value1",
							"key2": "value2",
						},
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"unrelated-label": "here",
							"key1":            "value1",
							"key2":            "value2",
						},
					},
				},
			},
		},
		{
			description: "Podname does not match",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						PodName:   "this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "a-misnamed-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Digest matches (full)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee",
					},
				},
			},
		},
		{
			description: "Digest match (short filter)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "e3652a00a2fa",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee",
					},
				},
			},
		},
		{
			description: "Digest match (implicit sha256 removal in filter)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:e3652a00a2fa",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee",
					},
				},
			},
		},
		{
			description: "Digest mismatch",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:ffffffffffff",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee",
					},
				},
			},
		},
		{
			description: "Digest filter but container digest empty",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:e3652a00a2fa",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{},
				},
			},
		},
		{
			description: "ImageID matches (full)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageID: "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageID: "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
					},
				},
			},
		},
		{
			description: "ImageID matches (short)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageID: "abcdabcdabcd",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageID: "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
					},
				},
			},
		},
		{
			description: "ImageID mismatch",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageID: "sha256:ffffffffffff",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageID: "sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
					},
				},
			},
		},
		{
			description: "One label doesn't match",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value1",
							"key2": "value2",
						},
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value1",
							"key2": "something-else",
						},
					},
				},
			},
		},
		{
			description: "Several namespaces without match",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "ns1,ns2,ns3",
						PodName:   "this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Several namespaces with match",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "ns1,ns2,ns3",
						PodName:   "this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "ns2",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by name shouldn't return a result with the excluded container name",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "!this-container",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by name returns a result without the excluded container name",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "!other-container",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by namespace shouldn't return a result with the excluded namespace",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "!this-namespace",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by namespace returns a result without the excluded namespace",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "!this-namespace",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "other-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by pod name shouldn't return a result with the excluded pod name",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodName: "!this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by pod name returns a result without the excluded pod name",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodName: "!this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "other-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Exclude container by pod label shouldn't return a result with the excluded pod label",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodLabels: map[string]string{
							"!key1": "value1",
						},
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value1",
						},
					},
				},
			},
		},
		{
			description: "Exclude container by pod label should return a result without the excluded pod label",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodLabels: map[string]string{
							"!key1": "value1",
						},
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value2",
							"key2": "value2",
						},
					},
				},
			},
		},
		{
			description: "Exclude container by pod label value shouldn't return a result with the excluded value",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodLabels: map[string]string{
							"key1": "!value1",
						},
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value1",
						},
					},
				},
			},
		},
		{
			description: "Exclude container by pod label value should return a result without the excluded value",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						PodLabels: map[string]string{
							"key1": "!value1",
						},
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
						PodLabels: map[string]string{
							"key1": "value2",
						},
					},
				},
			},
		},
		{
			description: "Exclude container by runtime container name shouldn't return a result with the excluded container name",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerName: "!runtime-container",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerName: "runtime-container",
					},
				},
			},
		},
		{
			description: "Mixed inclusion and exclusion should return a match",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						PodName:   "!other-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Mixed inclusion and exclusion shouldn't return a match",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: "this-namespace",
						PodName:   "!this-pod",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "this-container",
					},
				},
			},
		},
		{
			description: "Several container names with match",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "c1,c2,c3",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "c2",
					},
				},
			},
		},
		{
			description: "Several container names without match",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "c1,c2,c3",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "c4",
					},
				},
			},
		},
		{
			description: "Exclude multiple container names retuns a result without the excluded container names",
			match:       true,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "!c1,!c2",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "c3",
					},
				},
			},
		},
		{
			description: "Exclude multiple container names shouldn't return a result with the excluded container names",
			match:       false,
			selector: &ContainerSelector{
				K8s: K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						ContainerName: "!c1,!c2",
					},
				},
			},
			container: &Container{
				K8s: K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "this-namespace",
						PodName:       "this-pod",
						ContainerName: "c1",
					},
				},
			},
		},
		{
			description: "Several runtime container names with match",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerName: "rc1,rc2,rc3",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerName: "rc2",
					},
				},
			},
		},
		{
			description: "Several runtime container names without match",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerName: "rc1,rc2,rc3",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerName: "rc4",
					},
				},
			},
		},
		{
			description: "Match by image digest",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "digest1",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "digest1",
					},
				},
			},
		},
		{
			description: "Image digest does not match",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "digest1",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "digest2",
					},
				},
			},
		},
		{
			description: "Exclude container by image digest shouldn't return a result with the excluded image digest",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "!digest1",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "digest1",
					},
				},
			},
		},
		{
			description: "Exclude container by image digest returns a result without the excluded image digest",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "!digest1",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "digest2",
					},
				},
			},
		},
		{
			description: "Several image digests with match",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "digest1,digest2",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "digest2",
					},
				},
			},
		},
		{
			description: "Match by partial image digest (12 chars)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:123456789012",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:1234567890123456",
					},
				},
			},
		},
		{
			description: "Match by long image digest (truncated to 12 chars)",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:1234567890123456",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:1234567890123456",
					},
				},
			},
		},
		{
			description: "Match by image digest without prefix",
			match:       true,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "123456789012",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:1234567890123456",
					},
				},
			},
		},
		{
			description: "Digest filter does not match ContainerImageName (no fallback)",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "123456789012",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "",
						ContainerImageName:   "sha256:1234567890123456",
					},
				},
			},
		},
		{
			description: "Mismatch by partial image digest",
			match:       false,
			selector: &ContainerSelector{
				Runtime: RuntimeSelector{
					ContainerImageDigest: "sha256:12345",
				},
			},
			container: &Container{
				Runtime: RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerImageDigest: "sha256:6789067890123456",
					},
				},
			},
		},
	}

	for i, entry := range table {
		result := ContainerSelectorMatches(entry.selector, entry.container)
		require.Equal(t, entry.match, result, "Failed test %q (index %d)", entry.description, i)
	}
}

func TestContainerResolver(t *testing.T) {
	opts := []ContainerCollectionOption{}

	cc := &ContainerCollection{}
	err := cc.Initialize(opts...)
	require.NoError(t, err, "Failed to initialize container collection")

	// Add 3 Containers
	for i := 0; i < 3; i++ {
		cc.AddContainer(&Container{
			Runtime: RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:  fmt.Sprintf("abcde%d", i),
					ContainerPID: uint32(100 + i),
				},
			},
			Mntns:      55555 + uint64(i),
			CgroupPath: "/none",
			CgroupID:   1,
			K8s: K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "this-namespace",
					PodName:       "my-pod",
					ContainerName: fmt.Sprintf("container%d", i),
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
	require.Equal(t, 2, cc.ContainerLen(), "Error while checking containers")
	require.NotNil(t, cc.GetContainer("abcde0"), "Error while checking container %s: not found", "abcde0")
	require.NotNil(t, cc.GetContainer("abcde2"), "Error while checking container %s: not found", "abcde2")

	// Check content using LookupMntnsByPod
	mntnsByContainer := cc.LookupMntnsByPod("this-namespace", "my-pod")
	require.Equal(t, map[string]uint64{"container0": 55555, "container2": 55557}, mntnsByContainer, "Error while looking up mount ns by Pod")

	mntnsByContainer = cc.LookupMntnsByPod("this-namespace", "this-other-pod")
	require.Equal(t, map[string]uint64{}, mntnsByContainer, "Error while looking up mount ns by Pod")

	// Check content using LookupMntnsByContainer
	mntns := cc.LookupMntnsByContainer("this-namespace", "my-pod", "container0")
	require.Equal(t, uint64(55555), mntns, "Error while looking up container0")

	mntns = cc.LookupMntnsByContainer("this-namespace", "my-pod", "container1")
	require.Equal(t, uint64(0), mntns, "Error while looking up container1")

	mntns = cc.LookupMntnsByContainer("this-namespace", "my-pod", "container2")
	require.Equal(t, uint64(55557), mntns, "Error while looking up container2")

	// Check content using LookupPIDByPod
	pidByContainer := cc.LookupPIDByPod("this-namespace", "my-pod")
	require.Equal(t, map[string]uint32{"container0": 100, "container2": 102}, pidByContainer, "Error while looking up PID by Pod")

	pidByContainer = cc.LookupPIDByPod("this-namespace", "this-other-pod")
	require.Equal(t, map[string]uint32{}, pidByContainer, "Error while looking up PID by Pod")

	// Check content using LookupPIDByContainer
	pid := cc.LookupPIDByContainer("this-namespace", "my-pod", "container0")
	require.Equal(t, uint32(100), pid, "Error while looking up container0")

	pid = cc.LookupPIDByContainer("this-namespace", "my-pod", "container1")
	require.Equal(t, uint32(0), pid, "Error while looking up container1")

	pid = cc.LookupPIDByContainer("this-namespace", "my-pod", "container2")
	require.Equal(t, uint32(102), pid, "Error while looking up container2")

	// Check content using LookupOwnerReferenceByMntns
	ownerRef := cc.LookupOwnerReferenceByMntns(55555)
	require.NotNil(t, ownerRef, "Error while looking up owner reference")
	require.Equal(t, k8sTypes.UID("abcde0"), ownerRef.UID, "Error while looking up owner reference")

	ownerRef = cc.LookupOwnerReferenceByMntns(55557)
	require.NotNil(t, ownerRef, "Error while looking up owner reference")
	require.Equal(t, k8sTypes.UID("abcde2"), ownerRef.UID, "Error while looking up owner reference")

	// Non-existent mntns
	ownerRef = cc.LookupOwnerReferenceByMntns(55556)
	require.Nil(t, ownerRef, "Error while looking up owner reference")

	// Check LookupContainerByMntns
	containerByMntns0 := cc.LookupContainerByMntns(55555)
	require.Equal(t, "container0", containerByMntns0.K8s.ContainerName, "Error in LookupContainerByMntns")

	// Check LookupContainerByMntns
	containerByMntns2 := cc.LookupContainerByMntns(55555 + 2)
	require.Equal(t, "container2", containerByMntns2.K8s.ContainerName, "Error in LookupContainerByMntns")

	containerByMntnsNotFound := cc.LookupContainerByMntns(989898)
	require.Nil(t, containerByMntnsNotFound, "Error in LookupContainerByMntns: returned non nil")

	// Add new container with same pod and container name of container0 but in different namespace
	cc.AddContainer(&Container{
		Runtime: RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "abcde0-different",
			},
		},
		K8s: K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "another-namespace",
				PodName:       "my-pod",
				ContainerName: "container0",
				PodLabels: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
	})

	// Look up containers with label 'key1=value1'
	selectedContainers := cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				PodLabels: map[string]string{
					"key1": "value1",
				},
			},
		},
	})
	require.Len(t, selectedContainers, 1, "Error while looking up containers by one label")
	v, found := selectedContainers[0].K8s.PodLabels["key1"]
	require.True(t, found, "Error while looking up containers by one label")
	require.Equal(t, "value1", v, "Error while looking up containers by one label")

	// Look up containers with label 'key1=value1' and 'key2=value2'
	selector := ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				PodLabels: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
	}
	selectedContainers = cc.GetContainersBySelector(&selector)
	require.Len(t, selectedContainers, 1, "Error while looking up containers by multiple labels: invalid number of matches")
	for sk, sv := range selector.K8s.PodLabels {
		v, found := selectedContainers[0].K8s.PodLabels[sk]
		require.True(t, found, "Error while looking up containers by multiple labels: missing label %q in container %+v",
			sk, selectedContainers[0])
		require.Equal(t, sv, v, "Error while looking up containers by multiple labels: unexpected container %+v",
			selectedContainers[0])
	}

	// Look up containers in 'this-namespace'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
			},
		},
	})
	require.Len(t, selectedContainers, 2, "Error while looking up containers by namespace: invalid number of matches")
	for _, container := range selectedContainers {
		require.Equal(t, "this-namespace", container.K8s.Namespace,
			"Error while looking up containers by namespace: unexpected container %+v", container)
	}

	// Look up containers in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				PodName:   "my-pod",
			},
		},
	})
	require.Len(t, selectedContainers, 2, "Error while looking up containers by namespace and pod: invalid number of matches")
	for _, container := range selectedContainers {
		require.Equal(t, "this-namespace", container.K8s.Namespace, "Error while looking up containers by namespace and pod: unexpected container %+v", container)
		require.Equal(t, "my-pod", container.K8s.PodName, "Error while looking up containers by namespace and pod: unexpected container %+v", container)
	}

	// Look up containers named 'container0' anywhere
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				ContainerName: "container0",
			},
		},
	})
	require.Len(t, selectedContainers, 2, "Error while looking up containers by name: invalid number of matches")
	for _, container := range selectedContainers {
		require.Equal(t, "container0", container.K8s.ContainerName,
			"Error while looking up containers by name: unexpected container %+v", container)
	}

	// Look up containers named 'container0' in 'my-pod' but any namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				PodName:       "my-pod",
				ContainerName: "container0",
			},
		},
	})
	require.Len(t, selectedContainers, 2, "Error while looking up containers by name and pod: invalid number of matches")
	for _, container := range selectedContainers {
		require.Equal(t, "my-pod", container.K8s.PodName, "Error while looking up containers by name and pod: unexpected container %+v", container)
		require.Equal(t, "container0", container.K8s.ContainerName, "Error while looking up containers by name and pod: unexpected container %+v", container)
	}

	// Look up container0 in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "this-namespace",
				PodName:       "my-pod",
				ContainerName: "container0",
			},
		},
	})
	require.Len(t, selectedContainers, 1, "Error while looking up specific container: invalid number of matches")
	require.Equal(t, "this-namespace", selectedContainers[0].K8s.Namespace, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])
	require.Equal(t, "my-pod", selectedContainers[0].K8s.PodName, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])
	require.Equal(t, "container0", selectedContainers[0].K8s.ContainerName, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])

	// Look up container0 in 'another-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "another-namespace",
				PodName:       "my-pod",
				ContainerName: "container0",
			},
		},
	})
	require.Len(t, selectedContainers, 1, "Error while looking up specific container: invalid number of matches")
	require.Equal(t, "another-namespace", selectedContainers[0].K8s.Namespace, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])
	require.Equal(t, "my-pod", selectedContainers[0].K8s.PodName, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])
	require.Equal(t, "container0", selectedContainers[0].K8s.ContainerName, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])

	// Look up container2 in 'this-namespace' and 'my-pod'
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "this-namespace",
				PodName:       "my-pod",
				ContainerName: "container2",
			},
		},
	})
	require.Len(t, selectedContainers, 1, "Error while looking up specific container: invalid number of matches")
	require.Equal(t, "this-namespace", selectedContainers[0].K8s.Namespace, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])
	require.Equal(t, "my-pod", selectedContainers[0].K8s.PodName, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])
	require.Equal(t, "container2", selectedContainers[0].K8s.ContainerName, "Error while looking up specific container: unexpected container %+v", selectedContainers[0])

	// Look up a non-existent container
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "this-namespace",
				PodName:       "my-pod",
				ContainerName: "non-existent",
			},
		},
	})
	require.Empty(t, selectedContainers, "Error while looking up a non-existent container")

	// Look up containers in a non-existent pod
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "this-namespace",
				PodName:   "non-existent",
			},
		},
	})
	require.Empty(t, selectedContainers, "Error while looking up containers in a non-existent pod")

	// Look up containers in a non-existent pod
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "this-namespace",
				PodName:       "non-existent",
				ContainerName: "container0",
			},
		},
	})
	require.Empty(t, selectedContainers, "Error while looking up containers in a non-existent namespace")

	// Look up containers in a non-existent namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: "non-existent",
			},
		},
	})
	require.Empty(t, selectedContainers, "Error while looking up containers in a non-existent namespace")

	// Look up containers in a non-existent namespace
	selectedContainers = cc.GetContainersBySelector(&ContainerSelector{
		K8s: K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "non-existent",
				PodName:       "my-pod",
				ContainerName: "container0",
			},
		},
	})
	require.Empty(t, selectedContainers, "Error while looking up containers in a non-existent namespace")
}

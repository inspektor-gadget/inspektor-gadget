// Copyright 2022 The Inspektor Gadget authors
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

package ociannotations

import "testing"

func Test_crioResolver(t *testing.T) {
	annotations := map[string]string{
		crioPodNameAnnotation:       "test-pod-name",
		crioPodNamespaceAnnotation:  "test-pod-namespace",
		crioPodUIDAnnotation:        "test-pod-uid",
		crioContainerNameAnnotation: "test-container-name",
		crioContainerTypeAnnotation: "test-container-type",
		crioContainerImageName:      "test-container-image-name",
	}

	resolver := crioResolver{}
	assert := func(got string, want string) {
		if got != want {
			t.Fatalf("Assertion failed got=%s, want=%s", got, want)
		}
	}

	t.Logf("Test resolving annotations for %s", resolver.Runtime())
	assert(resolver.PodName(annotations), "test-pod-name")
	assert(resolver.PodNamespace(annotations), "test-pod-namespace")
	assert(resolver.PodUID(annotations), "test-pod-uid")
	assert(resolver.ContainerName(annotations), "test-container-name")
	assert(resolver.ContainerType(annotations), "test-container-type")
	assert(resolver.ContainerImageName(annotations), "test-container-image-name")
}

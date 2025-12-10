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

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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

	t.Logf("Test resolving annotations for %s", resolver.Runtime())
	require.Equal(t, "test-pod-name", resolver.PodName(annotations))
	require.Equal(t, "test-pod-namespace", resolver.PodNamespace(annotations))
	require.Equal(t, "test-pod-uid", resolver.PodUID(annotations))
	require.Equal(t, "test-container-name", resolver.ContainerName(annotations))
	require.Equal(t, "test-container-type", resolver.ContainerType(annotations))
	require.Equal(t, "test-container-image-name", resolver.ContainerImageName(annotations))
}

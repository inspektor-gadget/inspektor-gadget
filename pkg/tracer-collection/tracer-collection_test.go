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

package tracercollection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestTracer(t *testing.T) {
	var cc containercollection.ContainerCollection
	cc.Initialize([]containercollection.ContainerCollectionOption{}...)

	tc, err := NewTracerCollectionTest(&cc)
	require.NoError(t, err, "Failed to create tracer collection")
	require.NotNil(t, tc, "Tracer collection is nil")

	// Add 3 Tracers
	for i := range 3 {
		err := tc.AddTracer(
			fmt.Sprintf("my_tracer_id%d", i),
			containercollection.ContainerSelector{
				K8s: containercollection.K8sSelector{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace: fmt.Sprintf("this-namespace%d", i),
					},
				},
			},
		)
		require.NoError(t, err, "Failed to add tracer")
	}

	// Check Tracer count
	require.Equal(t, 3, tc.TracerCount(), "Tracer count mismatch after adding tracers")

	// Check error on duplicate tracer
	err = tc.AddTracer(
		fmt.Sprintf("my_tracer_id%d", 0),
		containercollection.ContainerSelector{
			K8s: containercollection.K8sSelector{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace: fmt.Sprintf("this-namespace%d", 0),
				},
			},
		},
	)
	require.Error(t, err, "Expected error when adding duplicate tracer")

	// Remove 1 Tracer
	require.NoError(t, tc.RemoveTracer(fmt.Sprintf("my_tracer_id%d", 1)), "Failed to remove tracer")

	// Remove non-existent Tracer
	require.Error(t, tc.RemoveTracer(fmt.Sprintf("my_tracer_id%d", 99)), "Expected error when removing non-existent tracer")

	// Check content
	require.Equal(t, 2, tc.TracerCount(), "Error while checking tracers")
	require.True(t, tc.TracerExists("my_tracer_id0"), "Error while checking tracer my_tracer_id0: not found")
	require.True(t, tc.TracerExists("my_tracer_id2"), "Error while checking tracer my_tracer_id2: not found")
}

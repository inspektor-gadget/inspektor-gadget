// Copyright 2026 The Inspektor Gadget authors
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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestNormalizeCommonData(t *testing.T) {
	// NormalizeCommonData behaves differently depending on the current test
	// component; force the kubectl-gadget (Kubernetes) path and restore it
	// afterwards.
	orig := CurrentTestComponent
	CurrentTestComponent = KubectlGadgetTestComponent
	t.Cleanup(func() { CurrentTestComponent = orig })

	t.Run("strips cloud-injected topology labels", func(t *testing.T) {
		e := &eventtypes.CommonData{
			K8s: eventtypes.K8sMetadata{
				BasicK8sMetadata: eventtypes.BasicK8sMetadata{
					PodName:       "test-pod",
					ContainerName: "test-pod",
					PodLabels: map[string]string{
						"run":                           "test-pod",
						"topology.kubernetes.io/region": "eastus2",
						"topology.kubernetes.io/zone":   "0",
						"failure-domain.beta.kubernetes.io/region": "eastus2",
						"failure-domain.beta.kubernetes.io/zone":   "0",
					},
				},
			},
		}

		NormalizeCommonData(e)

		assert.Equal(t, map[string]string{"run": "test-pod"}, e.K8s.PodLabels,
			"cloud-injected topology labels should be stripped, leaving only user labels")
	})

	t.Run("leaves user labels untouched", func(t *testing.T) {
		e := &eventtypes.CommonData{
			K8s: eventtypes.K8sMetadata{
				BasicK8sMetadata: eventtypes.BasicK8sMetadata{
					PodLabels: map[string]string{"run": "test-pod"},
				},
			},
		}

		NormalizeCommonData(e)

		assert.Equal(t, map[string]string{"run": "test-pod"}, e.K8s.PodLabels)
	})

	t.Run("nil pod labels are safe", func(t *testing.T) {
		e := &eventtypes.CommonData{}

		assert.NotPanics(t, func() { NormalizeCommonData(e) })
		assert.Nil(t, e.K8s.PodLabels)
	})

	t.Run("normalizes other non-deterministic fields", func(t *testing.T) {
		e := &eventtypes.CommonData{
			Runtime: eventtypes.BasicRuntimeMetadata{
				RuntimeName:          eventtypes.RuntimeNameContainerd,
				ContainerName:        "test-pod",
				ContainerPID:         4242,
				ContainerImageDigest: "sha256:deadbeef",
				ContainerStartedAt:   eventtypes.Time(1234567890),
			},
			K8s: eventtypes.K8sMetadata{
				Node: "some-node",
			},
		}

		NormalizeCommonData(e)

		assert.Empty(t, e.Runtime.ContainerImageDigest)
		assert.Zero(t, e.Runtime.ContainerPID)
		assert.Zero(t, e.Runtime.ContainerStartedAt)
		assert.Empty(t, e.K8s.Node)
		assert.Empty(t, string(e.Runtime.RuntimeName))
		assert.Empty(t, e.Runtime.ContainerName)
	})
}

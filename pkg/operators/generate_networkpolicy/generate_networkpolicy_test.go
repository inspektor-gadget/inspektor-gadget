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

package generate_networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestLabelFilterIgnoresNonIdentityLabels(t *testing.T) {
	in := map[string]string{
		"app":                           "backend",
		"run":                           "backend",
		"pod-template-hash":             "abc123",
		"topology.kubernetes.io/region": "us-east1",
		"topology.kubernetes.io/zone":   "us-east1-c",
		"failure-domain.beta.kubernetes.io/region": "us-east1",
		"failure-domain.beta.kubernetes.io/zone":   "us-east1-c",
	}

	// Only user-defined workload-identity labels must survive; node-derived
	// topology labels and ephemeral controller labels must be filtered out.
	assert.Equal(t, map[string]string{"app": "backend", "run": "backend"}, labelFilter(in))

	// labelFilteredKeyList must be consistent with labelFilter.
	assert.Equal(t, []string{"app", "run"}, labelFilteredKeyList(in))
}

func TestHandleCiliumEvents_IgnoresTopologyLabels(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(false, "prod",
			map[string]string{
				"app":                           "backend",
				"topology.kubernetes.io/region": "us-east1",
				"topology.kubernetes.io/zone":   "us-east1-c",
			},
			types.EndpointKindPod, "prod",
			map[string]string{
				"app":                           "frontend",
				"topology.kubernetes.io/region": "us-east1",
				"topology.kubernetes.io/zone":   "us-east1-d",
			},
			"", 8080, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	p := policies[0]
	// Topology labels must not leak into the generated selectors.
	assert.Equal(t, map[string]string{"app": "backend"}, p.Spec.EndpointSelector.MatchLabels)

	require.Len(t, p.Spec.Ingress, 1)
	require.Len(t, p.Spec.Ingress[0].FromEndpoints, 1)
	assert.Equal(t, map[string]string{"app": "frontend"}, p.Spec.Ingress[0].FromEndpoints[0].MatchLabels)
}

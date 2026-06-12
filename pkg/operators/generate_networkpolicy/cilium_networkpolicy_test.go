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

func makeEvent(egress bool, localNs string, localLabels map[string]string, kind types.EndpointKind, peerNs string, peerLabels map[string]string, addr string, port uint16, proto string) NetworkEvent {
	e := NetworkEvent{
		egress: egress,
		K8s: types.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace: localNs,
				PodLabels: localLabels,
			},
		},
		endpoint: types.L4Endpoint{
			L3Endpoint: types.L3Endpoint{
				Kind:      kind,
				Namespace: peerNs,
				Addr:      addr,
			},
			Port: port,
		},
		proto: proto,
	}
	switch kind {
	case types.EndpointKindPod:
		e.endpoint.PodLabels = peerLabels
	case types.EndpointKindService:
		e.endpoint.PodSelector = peerLabels
	}
	return e
}

func TestHandleCiliumEvents_SameNamespacePod(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(false, "prod", map[string]string{"app": "backend"},
			types.EndpointKindPod, "prod", map[string]string{"app": "frontend"},
			"", 8080, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	p := policies[0]
	assert.Equal(t, "cilium.io/v2", p.APIVersion)
	assert.Equal(t, "CiliumNetworkPolicy", p.Kind)
	assert.Equal(t, "prod", p.Namespace)
	assert.Equal(t, map[string]string{"app": "backend"}, p.Spec.EndpointSelector.MatchLabels)

	require.Len(t, p.Spec.Ingress, 1)
	ingress := p.Spec.Ingress[0]
	require.Len(t, ingress.FromEndpoints, 1)
	// Same namespace: no io.kubernetes.pod.namespace label
	assert.Equal(t, map[string]string{"app": "frontend"}, ingress.FromEndpoints[0].MatchLabels)
	require.Len(t, ingress.ToPorts, 1)
	assert.Equal(t, "8080", ingress.ToPorts[0].Ports[0].Port)
	assert.Equal(t, "TCP", ingress.ToPorts[0].Ports[0].Protocol)

	assert.Empty(t, p.Spec.Egress)
}

func TestHandleCiliumEvents_CrossNamespacePod(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(true, "prod", map[string]string{"app": "backend"},
			types.EndpointKindPod, "monitoring", map[string]string{"app": "prometheus"},
			"", 9090, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	egress := policies[0].Spec.Egress
	require.Len(t, egress, 1)
	require.Len(t, egress[0].ToEndpoints, 1)
	// Cross-namespace: io.kubernetes.pod.namespace must be present
	labels := egress[0].ToEndpoints[0].MatchLabels
	assert.Equal(t, "monitoring", labels["io.kubernetes.pod.namespace"])
	assert.Equal(t, "prometheus", labels["app"])
}

func TestHandleCiliumEvents_RawIP_Egress(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(true, "prod", map[string]string{"app": "backend"},
			types.EndpointKindRaw, "", nil,
			"93.184.216.34", 443, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	egress := policies[0].Spec.Egress
	require.Len(t, egress, 1)
	assert.Equal(t, []string{"93.184.216.34/32"}, egress[0].ToCIDR)
	assert.Empty(t, egress[0].ToEndpoints)
}

func TestHandleCiliumEvents_Localhost_Skipped(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(true, "prod", map[string]string{"app": "backend"},
			types.EndpointKindRaw, "", nil,
			"127.0.0.1", 8080, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	// Localhost traffic must not produce any egress rule
	assert.Empty(t, policies[0].Spec.Egress)
}

func TestHandleCiliumEvents_PortAggregation(t *testing.T) {
	// Two events to the same peer, different ports — must produce ONE rule with both ports.
	base := makeEvent(true, "prod", map[string]string{"app": "backend"},
		types.EndpointKindPod, "prod", map[string]string{"app": "db"},
		"", 5432, "TCP")
	extra := base
	extra.endpoint.Port = 5433

	eventsBySource := map[string][]NetworkEvent{
		localPodKey(base): {base, extra},
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	egress := policies[0].Spec.Egress
	require.Len(t, egress, 1, "same peer → single egress rule")
	require.Len(t, egress[0].ToPorts, 1)
	assert.Len(t, egress[0].ToPorts[0].Ports, 2, "both ports must be listed in the same rule")
}

func TestHandleCiliumEvents_PortDeduplication(t *testing.T) {
	// Same port observed twice (e.g. two separate connections) — must appear only once.
	base := makeEvent(true, "prod", map[string]string{"app": "backend"},
		types.EndpointKindPod, "prod", map[string]string{"app": "db"},
		"", 5432, "TCP")

	eventsBySource := map[string][]NetworkEvent{
		localPodKey(base): {base, base},
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Len(t, policies[0].Spec.Egress[0].ToPorts[0].Ports, 1)
}

func TestHandleCiliumEvents_Service(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(false, "prod", map[string]string{"app": "frontend"},
			types.EndpointKindService, "prod", map[string]string{"app": "backend"},
			"", 80, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 1)

	ingress := policies[0].Spec.Ingress
	require.Len(t, ingress, 1)
	require.Len(t, ingress[0].FromEndpoints, 1)
	assert.Equal(t, map[string]string{"app": "backend"}, ingress[0].FromEndpoints[0].MatchLabels)
}

func TestFormatCiliumPolicies_YAMLOutput(t *testing.T) {
	events := []NetworkEvent{
		makeEvent(true, "prod", map[string]string{"app": "backend"},
			types.EndpointKindRaw, "", nil,
			"1.2.3.4", 443, "TCP"),
	}
	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events[0]): events,
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)

	out := FormatCiliumPolicies(policies)
	assert.Contains(t, out, "cilium.io/v2")
	assert.Contains(t, out, "CiliumNetworkPolicy")
	assert.Contains(t, out, "toCIDR")
	assert.Contains(t, out, "1.2.3.4/32")
	assert.Contains(t, out, `port: "443"`)
}

func TestFormatCiliumPolicies_MultipleDocumentSeparator(t *testing.T) {
	events1 := makeEvent(true, "prod", map[string]string{"app": "a"},
		types.EndpointKindRaw, "", nil, "1.1.1.1", 80, "TCP")
	events2 := makeEvent(true, "prod", map[string]string{"app": "b"},
		types.EndpointKindRaw, "", nil, "2.2.2.2", 80, "TCP")

	eventsBySource := map[string][]NetworkEvent{
		localPodKey(events1): {events1},
		localPodKey(events2): {events2},
	}

	policies, err := handleCiliumEvents(eventsBySource)
	require.NoError(t, err)
	require.Len(t, policies, 2)

	out := FormatCiliumPolicies(policies)
	assert.Contains(t, out, "---\n", "multiple policies must be separated by ---")
}
